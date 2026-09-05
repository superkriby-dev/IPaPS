#![windows_subsystem = "windows"]

use eframe::egui;
use std::{
    collections::BTreeMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const TOTAL_PORTS: usize = 65_535;
const MAX_PORT_CONCURRENCY: usize = 1024;

#[derive(Clone, Debug)]
struct IpResult {
    ip: IpAddr,
    ping_ok: bool,
    rtt_ms: Option<u128>,
    reverse_dns: Option<String>,
    geo: Option<GeoInfo>,
    port_scan: Option<PortScanState>,
}

#[derive(Clone, Debug, Default)]
struct GeoInfo {
    country: String,
    region: String,
    city: String,
    isp: String,
    org: String,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Clone, Debug)]
struct PortScanState {
    completed: usize,
    total: usize,
    open: usize,
    closed: usize,
    filtered: usize,
    finished: bool,
    open_ports: Vec<u16>,
    started_at: Option<Instant>,
}

impl Default for PortScanState {
    fn default() -> Self {
        Self {
            completed: 0,
            total: TOTAL_PORTS,
            open: 0,
            closed: 0,
            filtered: 0,
            finished: false,
            open_ports: Vec::new(),
            started_at: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

enum WorkerMessage {
    Status(String),

    Resolved(Vec<IpAddr>),

    PingResult {
        ip: IpAddr,
        ok: bool,
        rtt_ms: Option<u128>,
    },

    ReverseDns {
        ip: IpAddr,
        hostname: Option<String>,
    },

    GeoResult {
        ip: IpAddr,
        info: Option<GeoInfo>,
    },

    PortScanStarted {
        ip: IpAddr,
        total: usize,
    },

    PortChecked {
        ip: IpAddr,
        port: u16,
        state: PortState,
    },

    PortScanFinished {
        ip: IpAddr,
    },

    Finished,

    Error(String),
}

#[derive(Default)]
struct App {
    domain: String,
    timeout_ms: u64,
    workers: usize,

    results: BTreeMap<IpAddr, IpResult>,

    status: String,
    running: bool,

    rx: Option<Receiver<WorkerMessage>>,
    tx: Option<Sender<WorkerMessage>>,
    cancel: Option<Arc<AtomicBool>>,

    selected_ip: Option<IpAddr>,
}

impl App {
    fn new() -> Self {
        Self {
            timeout_ms: 750,
            workers: 256,
            status: "Enter a domain and press Resolve / Inspect.".to_string(),
            ..Default::default()
        }
    }

    fn start_resolve(&mut self) {
        if self.running {
            return;
        }

        let domain = self.domain.trim().to_string();

        if domain.is_empty() {
            self.status = "Enter a domain first.".to_string();
            return;
        }

        self.results.clear();
        self.selected_ip = None;

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));

        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.cancel = Some(cancel.clone());
        self.running = true;

        let timeout_ms = self.timeout_ms;
        let workers = self.workers.max(1);

        thread::spawn(move || {
            resolve_and_test(
                domain,
                timeout_ms,
                workers,
                tx,
                cancel,
            );
        });
    }

    fn start_port_scan(&mut self, ip: IpAddr) {
        if self.running {
            return;
        }

        if let Some(result) = self.results.get_mut(&ip) {
            result.port_scan = Some(PortScanState::default());
        }

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));

        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.cancel = Some(cancel.clone());

        self.running = true;
        self.selected_ip = Some(ip);
        self.status = format!("Starting fast TCP scan for {ip}...");

        let timeout_ms = self.timeout_ms;

        /*
         * The port scanner uses Tokio internally, so the GUI itself
         * remains completely responsive.
         */
        thread::spawn(move || {
            scan_all_ports_async(
                ip,
                timeout_ms,
                tx,
                cancel,
            );
        });
    }

    fn stop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }

        self.running = false;
        self.cancel = None;
        self.tx = None;

        self.status = "Stopped.".to_string();
    }

    fn clear(&mut self) {
        if self.running {
            return;
        }

        self.results.clear();
        self.selected_ip = None;
        self.status = "Cleared.".to_string();
    }

    fn process_messages(&mut self) {
        let Some(rx) = self.rx.take() else {
            return;
        };

        let mut finished = false;

        /*
         * Drain everything available each frame so the port counter
         * stays as close to real-time as possible.
         */
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMessage::Status(text) => {
                    self.status = text;
                }

                WorkerMessage::Resolved(ips) => {
                    for ip in ips {
                        self.results.insert(
                            ip,
                            IpResult {
                                ip,
                                ping_ok: false,
                                rtt_ms: None,
                                reverse_dns: None,
                                geo: None,
                                port_scan: None,
                            },
                        );
                    }
                }

                WorkerMessage::PingResult {
                    ip,
                    ok,
                    rtt_ms,
                } => {
                    if let Some(result) = self.results.get_mut(&ip) {
                        result.ping_ok = ok;
                        result.rtt_ms = rtt_ms;
                    }
                }

                WorkerMessage::ReverseDns {
                    ip,
                    hostname,
                } => {
                    if let Some(result) = self.results.get_mut(&ip) {
                        result.reverse_dns = hostname;
                    }
                }

                WorkerMessage::GeoResult { ip, info } => {
                    if let Some(result) = self.results.get_mut(&ip) {
                        result.geo = info;
                    }
                }

                WorkerMessage::PortScanStarted { ip, total } => {
                    if let Some(result) = self.results.get_mut(&ip) {
                        result.port_scan = Some(PortScanState {
                            total,
                            started_at: Some(Instant::now()),
                            ..Default::default()
                        });
                    }

                    self.status =
                        format!("Scanning {ip}: 0 / {total}");
                }

                WorkerMessage::PortChecked {
                    ip,
                    port,
                    state,
                } => {
                    if let Some(result) = self.results.get_mut(&ip) {
                        if let Some(scan) = &mut result.port_scan {
                            scan.completed += 1;

                            match state {
                                PortState::Open => {
                                    scan.open += 1;

                                    if !scan.open_ports.contains(&port) {
                                        scan.open_ports.push(port);
                                        scan.open_ports.sort_unstable();
                                    }
                                }

                                PortState::Closed => {
                                    scan.closed += 1;
                                }

                                PortState::Filtered => {
                                    scan.filtered += 1;
                                }
                            }

                            let speed =
                                scan_speed(scan);

                            if speed > 0.0 {
                                let remaining =
                                    scan.total.saturating_sub(scan.completed);

                                let eta =
                                    remaining as f64 / speed;

                                self.status = format!(
                                    "Scanning {ip}: {} / {}  •  {:.0} ports/s  •  ETA {}",
                                    scan.completed,
                                    scan.total,
                                    speed,
                                    format_duration(eta)
                                );
                            } else {
                                self.status = format!(
                                    "Scanning {ip}: {} / {}",
                                    scan.completed,
                                    scan.total
                                );
                            }
                        }
                    }
                }

                WorkerMessage::PortScanFinished { ip } => {
                    if let Some(result) = self.results.get_mut(&ip) {
                        if let Some(scan) = &mut result.port_scan {
                            scan.completed = scan.total;
                            scan.finished = true;
                        }
                    }

                    self.status =
                        format!("Port scan finished for {ip}.");
                }

                WorkerMessage::Error(error) => {
                    self.status = format!("Error: {error}");
                    finished = true;
                }

                WorkerMessage::Finished => {
                    finished = true;
                }
            }
        }

        if !finished {
            self.rx = Some(rx);
        } else {
            self.running = false;
            self.cancel = None;
            self.tx = None;
        }
    }

    fn draw_header(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.heading(
                        egui::RichText::new(
                            "Network Inspector",
                        )
                        .strong(),
                    );

                    ui.label(
                        egui::RichText::new(
                            "DNS • Ping • Reverse DNS • Geolocation • TCP scanning",
                        )
                        .weak(),
                    );

                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.label("Domain");

                        ui.add(
                            egui::TextEdit::singleline(
                                &mut self.domain,
                            )
                            .hint_text("example.com")
                            .desired_width(320.0),
                        );

                        if ui
                            .add_enabled(
                                !self.running,
                                egui::Button::new(
                                    egui::RichText::new(
                                        "Resolve / Inspect",
                                    )
                                    .strong(),
                                ),
                            )
                            .clicked()
                        {
                            self.start_resolve();
                        }

                        if ui
                            .add_enabled(
                                self.running,
                                egui::Button::new(
                                    egui::RichText::new("Stop"),
                                ),
                            )
                            .clicked()
                        {
                            self.stop();
                        }

                        if ui
                            .add_enabled(
                                !self.running,
                                egui::Button::new("Clear"),
                            )
                            .clicked()
                        {
                            self.clear();
                        }
                    });

                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.label("Timeout");

                        ui.add(
                            egui::DragValue::new(
                                &mut self.timeout_ms,
                            )
                            .range(100..=5000)
                            .suffix(" ms"),
                        );

                        ui.separator();

                        ui.label("DNS/Ping workers");

                        ui.add(
                            egui::DragValue::new(
                                &mut self.workers,
                            )
                            .range(1..=512),
                        );

                        ui.separator();

                        let state_text =
                            if self.running {
                                "RUNNING"
                            } else {
                                "IDLE"
                            };

                        ui.label(
                            egui::RichText::new(
                                state_text,
                            )
                            .strong(),
                        );
                    });
                });
            });
    }

    fn draw_summary(&self, ui: &mut egui::Ui) {
        let total_ips = self.results.len();

        let online = self
            .results
            .values()
            .filter(|r| r.ping_ok)
            .count();

        let scanned = self
            .results
            .values()
            .filter(|r| r.port_scan.is_some())
            .count();

        let open_ports: usize = self
            .results
            .values()
            .filter_map(|r| r.port_scan.as_ref())
            .map(|s| s.open)
            .sum();

        ui.horizontal_wrapped(|ui| {
            summary_card(
                ui,
                "Resolved",
                &total_ips.to_string(),
            );

            summary_card(
                ui,
                "Online",
                &online.to_string(),
            );

            summary_card(
                ui,
                "Scanned",
                &scanned.to_string(),
            );

            summary_card(
                ui,
                "Open ports",
                &open_ports.to_string(),
            );
        });
    }

    fn draw_results(&mut self, ui: &mut egui::Ui) {
        if self.results.is_empty() {
            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::same(30))
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("Nothing to display yet");
                        ui.label(
                            "Enter a domain above and resolve it.",
                        );
                    });
                });

            return;
        }

        let ips: Vec<IpAddr> =
            self.results.keys().copied().collect();

        for ip in ips {
            let Some(result) =
                self.results.get(&ip).cloned()
            else {
                continue;
            };

            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(format!("{}", result.ip));

                        if result.ip.is_ipv4() {
                            badge(ui, "IPv4");
                        } else {
                            badge(ui, "IPv6");
                        }

                        if result.ping_ok {
                            online_badge(ui);
                        } else {
                            badge(ui, "NO REPLY");
                        }
                    });

                    ui.add_space(8.0);

                    ui.horizontal_wrapped(|ui| {
                        info_item(
                            ui,
                            "RTT",
                            &result
                                .rtt_ms
                                .map(|v| format!("{v} ms"))
                                .unwrap_or_else(|| "-".to_string()),
                        );

                        info_item(
                            ui,
                            "Reverse DNS",
                            result
                                .reverse_dns
                                .as_deref()
                                .unwrap_or("-"),
                        );

                        let location = result
                            .geo
                            .as_ref()
                            .map(|geo| {
                                format!(
                                    "{}, {}, {}",
                                    empty_dash(&geo.city),
                                    empty_dash(&geo.region),
                                    empty_dash(&geo.country)
                                )
                            })
                            .unwrap_or_else(|| "-".to_string());

                        info_item(
                            ui,
                            "Location",
                            &location,
                        );
                    });

                    if let Some(geo) = &result.geo {
                        ui.add_space(4.0);

                        ui.collapsing("Geolocation details", |ui| {
                            egui::Grid::new(format!(
                                "geo_{}",
                                result.ip
                            ))
                            .num_columns(2)
                            .spacing([18.0, 5.0])
                            .show(ui, |ui| {
                                detail_row(
                                    ui,
                                    "Country",
                                    &geo.country,
                                );

                                detail_row(
                                    ui,
                                    "Region",
                                    &geo.region,
                                );

                                detail_row(
                                    ui,
                                    "City",
                                    &geo.city,
                                );

                                detail_row(
                                    ui,
                                    "ISP",
                                    &geo.isp,
                                );

                                detail_row(
                                    ui,
                                    "Organization",
                                    &geo.org,
                                );

                                if let (
                                    Some(lat),
                                    Some(lon),
                                ) = (
                                    geo.latitude,
                                    geo.longitude,
                                ) {
                                    detail_row(
                                        ui,
                                        "Coordinates",
                                        &format!(
                                            "{lat:.5}, {lon:.5}"
                                        ),
                                    );
                                }
                            });
                        });
                    }

                    ui.add_space(8.0);

                    if let Some(scan) = &result.port_scan {
                        draw_port_scan(
                            ui,
                            &result,
                            scan,
                        );
                    } else if ui
                        .add_enabled(
                            !self.running,
                            egui::Button::new(
                                egui::RichText::new(
                                    "▶ Scan all 65,535 TCP ports",
                                )
                                .strong(),
                            ),
                        )
                        .clicked()
                    {
                        self.start_port_scan(result.ip);
                    }
                });
        }
    }
}

impl eframe::App for App {
    fn ui(
        &mut self,
        ui: &mut egui::Ui,
        _frame: &mut eframe::Frame,
    ) {
        self.process_messages();

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    self.draw_header(ui);

                    ui.add_space(10.0);

                    self.draw_summary(ui);

                    ui.add_space(10.0);

                    ui.label(
                        egui::RichText::new(&self.status)
                            .weak(),
                    );

                    ui.add_space(8.0);

                    self.draw_results(ui);
                });
        });

        if self.running {
            ui.ctx().request_repaint_after(
                Duration::from_millis(16),
            );
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(
                "Network Inspector",
            )
            .with_inner_size([1400.0, 850.0])
            .with_min_inner_size([1000.0, 650.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Network Inspector",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}

fn resolve_and_test(
    domain: String,
    timeout_ms: u64,
    workers: usize,
    tx: Sender<WorkerMessage>,
    cancel: Arc<AtomicBool>,
) {
    let _ = tx.send(WorkerMessage::Status(format!(
        "Resolving {domain}..."
    )));

    let lookup =
        match std::net::ToSocketAddrs::to_socket_addrs(
            &(domain.clone(), 0),
        ) {
            Ok(addrs) => addrs,

            Err(error) => {
                let _ = tx.send(
                    WorkerMessage::Error(format!(
                        "DNS resolution failed: {error}"
                    )),
                );

                return;
            }
        };

    let mut ips: Vec<IpAddr> =
        lookup.map(|addr| addr.ip()).collect();

    ips.sort();
    ips.dedup();

    if ips.is_empty() {
        let _ = tx.send(WorkerMessage::Error(
            "No IP addresses were found.".to_string(),
        ));

        return;
    }

    let _ =
        tx.send(WorkerMessage::Resolved(ips.clone()));

    let queue =
        Arc::new(std::sync::Mutex::new(ips));

    let worker_count =
        workers.clamp(1, 128);

    let mut handles =
        Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let cancel = Arc::clone(&cancel);

        handles.push(thread::spawn(move || loop {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let ip = {
                let mut queue =
                    queue.lock().expect(
                        "DNS worker queue poisoned",
                    );

                queue.pop()
            };

            let Some(ip) = ip else {
                break;
            };

            let (ping_ok, rtt_ms) =
                ping_ip(ip, timeout_ms);

            let _ =
                tx.send(WorkerMessage::PingResult {
                    ip,
                    ok: ping_ok,
                    rtt_ms,
                });

            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let hostname =
                reverse_dns(ip);

            let _ =
                tx.send(WorkerMessage::ReverseDns {
                    ip,
                    hostname,
                });

            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let geo =
                geolocate_ip(ip, timeout_ms);

            let _ =
                tx.send(WorkerMessage::GeoResult {
                    ip,
                    info: geo,
                });
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    if !cancel.load(Ordering::Relaxed) {
        let _ =
            tx.send(WorkerMessage::Finished);
    }
}

fn ping_ip(
    ip: IpAddr,
    timeout_ms: u64,
) -> (bool, Option<u128>) {
    let start = Instant::now();

    let ip_string = ip.to_string();

    let output =
        if cfg!(target_os = "windows") {
            let timeout =
                timeout_ms.to_string();

            if ip.is_ipv4() {
                Command::new("ping")
                    .args([
                        "-n",
                        "1",
                        "-w",
                        &timeout,
                        &ip_string,
                    ])
                    .output()
            } else {
                Command::new("ping")
                    .args([
                        "-6",
                        "-n",
                        "1",
                        "-w",
                        &timeout,
                        &ip_string,
                    ])
                    .output()
            }
        } else {
            let seconds = timeout_ms
                .div_ceil(1000)
                .max(1)
                .to_string();

            if ip.is_ipv4() {
                Command::new("ping")
                    .args([
                        "-c",
                        "1",
                        "-W",
                        &seconds,
                        &ip_string,
                    ])
                    .output()
            } else {
                Command::new("ping")
                    .args([
                        "-6",
                        "-c",
                        "1",
                        "-W",
                        &seconds,
                        &ip_string,
                    ])
                    .output()
            }
        };

    match output {
        Ok(output)
            if output.status.success() =>
        {
            (
                true,
                Some(
                    start.elapsed().as_millis(),
                ),
            )
        }

        _ => (false, None),
    }
}

fn reverse_dns(
    ip: IpAddr,
) -> Option<String> {
    let output =
        Command::new("nslookup")
            .arg(ip.to_string())
            .output()
            .ok()?;

    let stdout =
        String::from_utf8_lossy(
            &output.stdout,
        );

    let stderr =
        String::from_utf8_lossy(
            &output.stderr,
        );

    let combined =
        format!("{stdout}\n{stderr}");

    let ip_string = ip.to_string();

    for line in combined.lines() {
        let line = line.trim();

        if let Some(name) =
            line.strip_prefix("Name:")
        {
            let name = name.trim();

            if !name.is_empty()
                && !name.eq_ignore_ascii_case(
                    &ip_string,
                )
            {
                return Some(
                    name.trim_end_matches('.')
                        .to_string(),
                );
            }
        }
    }

    for line in combined.lines() {
        let line = line.trim();

        if let Some(name) =
            line.strip_prefix("name =")
        {
            let name = name.trim();

            if !name.is_empty() {
                return Some(
                    name.trim_end_matches('.')
                        .to_string(),
                );
            }
        }
    }

    None
}

fn geolocate_ip(
    ip: IpAddr,
    timeout_ms: u64,
) -> Option<GeoInfo> {
    if is_non_public_ip(ip) {
        return None;
    }

    let url =
        format!("https://ipwho.is/{ip}");

    let client =
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(
                timeout_ms.saturating_mul(3),
            ))
            .build()
            .ok()?;

    let response =
        client.get(url).send().ok()?;

    if !response.status().is_success() {
        return None;
    }

    let value:
        serde_json::Value =
        response.json().ok()?;

    if value
        .get("success")
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return None;
    }

    let country =
        json_string(&value, "country");

    let region =
        json_string(&value, "region");

    let city =
        json_string(&value, "city");

    let isp = value
        .get("connection")
        .and_then(|v| v.get("isp"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let org = value
        .get("connection")
        .and_then(|v| v.get("org"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let latitude =
        value.get("latitude")
            .and_then(|v| v.as_f64());

    let longitude =
        value.get("longitude")
            .and_then(|v| v.as_f64());

    Some(GeoInfo {
        country,
        region,
        city,
        isp,
        org,
        latitude,
        longitude,
    })
}

fn json_string(
    value: &serde_json::Value,
    key: &str,
) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn is_non_public_ip(
    ip: IpAddr,
) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            let o = addr.octets();

            addr.is_loopback()
                || addr.is_private()
                || addr.is_link_local()
                || addr.is_broadcast()
                || addr.is_unspecified()
                // 100.64.0.0/10
                || (o[0] == 100
                    && (64..=127).contains(
                        &o[1],
                    ))
                // 192.0.2.0/24
                || (o[0] == 192
                    && o[1] == 0
                    && o[2] == 2)
                // 198.51.100.0/24
                || (o[0] == 198
                    && o[1] == 51
                    && o[2] == 100)
                // 203.0.113.0/24
                || (o[0] == 203
                    && o[1] == 0
                    && o[2] == 113)
        }

        IpAddr::V6(addr) => {
            let s = addr.segments();

            addr.is_loopback()
                || addr.is_unspecified()
                // fc00::/7
                || ((s[0] & 0xfe00)
                    == 0xfc00)
                // fe80::/10
                || ((s[0] & 0xffc0)
                    == 0xfe80)
                // 2001:db8::/32
                || (s[0] == 0x2001
                    && s[1] == 0x0db8)
        }
    }
}

/*
 * FAST ASYNC TCP SCANNER
 *
 * Instead of blocking a thread on every connect(), this uses Tokio's
 * asynchronous TCP implementation.
 *
 * Up to MAX_PORT_CONCURRENCY sockets can be in-flight at once.
 */
fn scan_all_ports_async(
    ip: IpAddr,
    timeout_ms: u64,
    tx: Sender<WorkerMessage>,
    cancel: Arc<AtomicBool>,
) {
    let runtime =
        match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,

            Err(error) => {
                let _ = tx.send(
                    WorkerMessage::Error(format!(
                        "Failed to create async runtime: {error}"
                    )),
                );

                return;
            }
        };

    let result = runtime.block_on(
        async_scan_ports(
            ip,
            timeout_ms,
            tx.clone(),
            cancel.clone(),
        ),
    );

    if let Err(error) = result {
        let _ = tx.send(
            WorkerMessage::Error(error),
        );

        return;
    }

    if !cancel.load(Ordering::Relaxed) {
        let _ = tx.send(
            WorkerMessage::PortScanFinished {
                ip,
            },
        );

        let _ =
            tx.send(WorkerMessage::Finished);
    }
}

async fn async_scan_ports(
    ip: IpAddr,
    timeout_ms: u64,
    tx: Sender<WorkerMessage>,
    cancel: Arc<AtomicBool>,
) -> Result<(), String> {
    let _ =
        tx.send(WorkerMessage::PortScanStarted {
            ip,
            total: TOTAL_PORTS,
        });

    let semaphore =
        Arc::new(tokio::sync::Semaphore::new(
            MAX_PORT_CONCURRENCY,
        ));

    let mut set =
        tokio::task::JoinSet::<()>::new();

    for port in 1..=TOTAL_PORTS {
        if cancel.load(Ordering::Relaxed) {
            break;
        }

        let semaphore =
            Arc::clone(&semaphore);

        let tx = tx.clone();
        let cancel =
            Arc::clone(&cancel);

        set.spawn(async move {
            let permit =
                semaphore.acquire_owned().await;

            let Ok(_permit) = permit else {
                return;
            };

            if cancel.load(Ordering::Relaxed) {
                return;
            }

            let address =
                SocketAddr::new(
                    ip,
                    port as u16,
                );

            let connect =
                tokio::time::timeout(
                    Duration::from_millis(
                        timeout_ms,
                    ),
                    tokio::net::TcpStream::connect(
                        address,
                    ),
                )
                .await;

            let state = match connect {
                Ok(Ok(_stream)) => {
                    PortState::Open
                }

                Ok(Err(error))
                    if error.kind()
                        == ErrorKind::ConnectionRefused =>
                {
                    PortState::Closed
                }

                Ok(Err(_)) => {
                    PortState::Filtered
                }

                Err(_) => {
                    PortState::Filtered
                }
            };

            let _ =
                tx.send(WorkerMessage::PortChecked {
                    ip,
                    port: port as u16,
                    state,
                });
        });
    }

    while set.join_next().await.is_some() {
        if cancel.load(Ordering::Relaxed) {
            set.abort_all();
            break;
        }
    }

    Ok(())
}

fn draw_port_scan(
    ui: &mut egui::Ui,
    result: &IpResult,
    scan: &PortScanState,
) {
    ui.separator();

    ui.horizontal(|ui| {
        ui.strong("TCP Port Scanner");

        if scan.finished {
            badge(ui, "COMPLETE");
        } else {
            badge(ui, "SCANNING");
        }
    });

    ui.add_space(6.0);

    let progress =
        scan.completed as f32
            / scan.total.max(1) as f32;

    let progress_text = format!(
        "{}/{} ports",
        format_number(scan.completed),
        format_number(scan.total)
    );

    ui.add(
        egui::ProgressBar::new(progress)
            .desired_height(22.0)
            .text(progress_text),
    );

    ui.add_space(6.0);

    ui.horizontal_wrapped(|ui| {
        stat_chip(
            ui,
            "Scanned",
            &format_number(scan.completed),
        );

        stat_chip(
            ui,
            "Open",
            &format_number(scan.open),
        );

        stat_chip(
            ui,
            "Closed",
            &format_number(scan.closed),
        );

        stat_chip(
            ui,
            "Filtered",
            &format_number(scan.filtered),
        );

        if let Some(started) =
            scan.started_at
        {
            let elapsed =
                started.elapsed()
                    .as_secs_f64();

            if elapsed > 0.0 {
                let speed =
                    scan.completed as f64
                        / elapsed;

                stat_chip(
                    ui,
                    "Speed",
                    &format!(
                        "{:.0} ports/s",
                        speed
                    ),
                );

                if !scan.finished {
                    let remaining =
                        scan.total
                            .saturating_sub(
                                scan.completed,
                            );

                    let eta =
                        remaining as f64
                            / speed;

                    stat_chip(
                        ui,
                        "ETA",
                        &format_duration(
                            eta,
                        ),
                    );
                } else {
                    stat_chip(
                        ui,
                        "Time",
                        &format_duration(
                            elapsed,
                        ),
                    );
                }
            }
        }
    });

    if !scan.open_ports.is_empty() {
        ui.add_space(8.0);

        egui::CollapsingHeader::new(
            format!(
                "Open TCP ports ({})",
                scan.open_ports.len()
            ),
        )
        .default_open(true)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(
                        |ui| {
                            for port
                                in &scan.open_ports
                            {
                                let service =
                                    common_service(
                                        *port,
                                    );

                                let text =
                                    match service {
                                        Some(name) =>
                                            format!(
                                                "{port} • {name}"
                                            ),

                                        None =>
                                            port.to_string(),
                                    };

                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(
                                            text,
                                        ),
                                    ),
                                );
                            }
                        },
                    );
                });
        });
    }

    if scan.finished
        && scan.open_ports.is_empty()
    {
        ui.add_space(6.0);

        ui.label(
            egui::RichText::new(
                format!(
                    "No open TCP ports found on {}.",
                    result.ip
                ),
            )
            .weak(),
        );
    }
}

fn scan_speed(
    scan: &PortScanState,
) -> f64 {
    let Some(started) =
        scan.started_at
    else {
        return 0.0;
    };

    let elapsed =
        started.elapsed()
            .as_secs_f64();

    if elapsed <= 0.0 {
        return 0.0;
    }

    scan.completed as f64 / elapsed
}

fn format_duration(
    seconds: f64,
) -> String {
    if !seconds.is_finite()
        || seconds < 0.0
    {
        return "-".to_string();
    }

    let seconds =
        seconds.round() as u64;

    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!(
            "{}m {}s",
            seconds / 60,
            seconds % 60
        )
    } else {
        format!(
            "{}h {:02}m",
            seconds / 3600,
            (seconds % 3600) / 60
        )
    }
}

fn format_number(
    value: usize,
) -> String {
    let text =
        value.to_string();

    let mut out =
        String::with_capacity(
            text.len() + text.len() / 3,
        );

    for (i, ch) in text.chars().enumerate() {
        if i > 0
            && (text.len() - i) % 3 == 0
        {
            out.push(',');
        }

        out.push(ch);
    }

    out
}

fn summary_card(
    ui: &mut egui::Ui,
    title: &str,
    value: &str,
) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(title)
                        .weak(),
                );

                ui.label(
                    egui::RichText::new(value)
                        .size(22.0)
                        .strong(),
                );
            });
        });
}

fn stat_chip(
    ui: &mut egui::Ui,
    title: &str,
    value: &str,
) {
    egui::Frame::group(ui.style())
        .inner_margin(
            egui::Margin::symmetric(
                9,
                6,
            ),
        )
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(
                        format!("{title}:"),
                    )
                    .weak(),
                );

                ui.label(
                    egui::RichText::new(value)
                        .strong(),
                );
            });
        });
}

fn info_item(
    ui: &mut egui::Ui,
    title: &str,
    value: &str,
) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(title)
                .weak(),
        );

        ui.label(
            egui::RichText::new(value)
                .strong(),
        );
    });

    ui.add_space(18.0);
}

fn detail_row(
    ui: &mut egui::Ui,
    name: &str,
    value: &str,
) {
    ui.strong(name);
    ui.label(empty_dash(value));
    ui.end_row();
}

fn badge(
    ui: &mut egui::Ui,
    text: &str,
) {
    ui.label(
        egui::RichText::new(
            format!(" {text} "),
        )
        .strong(),
    );
}

fn online_badge(
    ui: &mut egui::Ui,
) {
    ui.label(
        egui::RichText::new(
            " ONLINE ",
        )
        .strong()
        .color(
            egui::Color32::from_rgb(
                60,
                190,
                100,
            ),
        ),
    );
}

fn empty_dash(
    value: &str,
) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}

fn common_service(
    port: u16,
) -> Option<&'static str> {
    match port {
        20 => Some("FTP-data"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        67 => Some("DHCP"),
        68 => Some("DHCP"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        111 => Some("RPC"),
        123 => Some("NTP"),
        135 => Some("MS RPC"),
        137 => Some("NetBIOS"),
        138 => Some("NetBIOS"),
        139 => Some("NetBIOS"),
        143 => Some("IMAP"),
        161 => Some("SNMP"),
        389 => Some("LDAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        465 => Some("SMTPS"),
        587 => Some("SMTP submission"),
        636 => Some("LDAPS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        5900 => Some("VNC"),
        6379 => Some("Redis"),
        8080 => Some("HTTP-alt"),
        8443 => Some("HTTPS-alt"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}