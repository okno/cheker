using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace ChekerDesktop {
    internal static class Program {
        [STAThread]
        private static void Main() {
            bool created;
            using (var mutex = new Mutex(true, "Local\\Cheker.Desktop", out created)) {
                if (!created) { MessageBox.Show("Cheker è già aperto. Cerca la sua finestra nella barra delle applicazioni.", "Cheker"); return; }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainWindow());
            }
        }
    }

    internal sealed class MainWindow : Form {
        private readonly string root = AppDomain.CurrentDomain.BaseDirectory;
        private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 8192 };
        private readonly Label status = new Label();
        private readonly Label detail = new Label();
        private readonly Button start = new Button();
        private readonly Panel welcome = new Panel();
        private readonly WebView2 view = new WebView2();
        private readonly ProgressBar progress = new ProgressBar();
        private Process bridge;
        private bool closing;
        private bool busy;
        private string origin;

        public MainWindow() {
            Text = "Cheker — Controllo documenti";
            Width = 1320; Height = 900; MinimumSize = new Size(920, 640);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(9, 19, 30); ForeColor = Color.White;
            Font = new Font("Segoe UI", 11);
            var header = new Panel { Dock = DockStyle.Top, Height = 54, BackColor = Color.FromArgb(14, 31, 44) };
            var title = new Label { Text = "CHEKER", Font = new Font("Segoe UI", 15, FontStyle.Bold), AutoSize = true, Location = new Point(20, 13) };
            status.Text = "Avvio guidato"; status.AutoSize = false; status.Location = new Point(160, 15); status.Size = new Size(940, 26);
            header.Controls.Add(title); header.Controls.Add(status);
            view.Dock = DockStyle.Fill; view.Visible = false;
            welcome.Dock = DockStyle.Fill; welcome.Padding = new Padding(45);
            var flow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };
            var logoPath = Path.Combine(root, "cheker.png");
            if (File.Exists(logoPath)) flow.Controls.Add(new PictureBox { Image = Image.FromFile(logoPath), Width = 100, Height = 100, SizeMode = PictureBoxSizeMode.Zoom, Margin = new Padding(0, 15, 0, 20) });
            flow.Controls.Add(new Label { Text = "I tuoi documenti, sotto controllo.", AutoSize = true, Font = new Font("Segoe UI", 26, FontStyle.Bold), Margin = new Padding(0, 0, 0, 20) });
            detail.Text = "Apri la dashboard, scegli i file e consulta risultati e contatori.\nIl motore gira localmente in Linux tramite WSL 2.";
            detail.AutoSize = true; detail.MaximumSize = new Size(920, 0); detail.Margin = new Padding(0, 0, 0, 24);
            flow.Controls.Add(detail);
            start.Text = "Apri Cheker"; start.Width = 250; start.Height = 52; start.FlatStyle = FlatStyle.Flat;
            start.BackColor = Color.FromArgb(56, 213, 183); start.ForeColor = Color.FromArgb(9, 19, 30);
            start.Click += async delegate { await StartAsync(); }; flow.Controls.Add(start);
            progress.Width = 600; progress.Height = 5; progress.Style = ProgressBarStyle.Marquee; progress.Visible = false; progress.Margin = new Padding(0, 20, 0, 20); flow.Controls.Add(progress);
            var help = new LinkLabel { Text = "Guida al primo avvio", AutoSize = true, LinkColor = Color.FromArgb(83, 224, 201), Margin = new Padding(0, 24, 0, 12) };
            help.LinkClicked += delegate { Process.Start(new ProcessStartInfo(Path.Combine(root, "LEGGIMI.html")) { UseShellExecute = true }); };
            flow.Controls.Add(help);
            var setup = new LinkLabel { Text = "Installare WSL 2 / WebView2", AutoSize = true, LinkColor = help.LinkColor };
            setup.LinkClicked += delegate { Process.Start(new ProcessStartInfo("https://learn.microsoft.com/windows/wsl/install") { UseShellExecute = true }); };
            flow.Controls.Add(setup);
            welcome.Controls.Add(flow); Controls.Add(view); Controls.Add(welcome); Controls.Add(header);
            FormClosing += CloseAsync;
            Shown += async delegate { await StartAsync(); };
        }

        private static string Quote(string argument) {
            // CommandLineToArgvW quoting, including a terminal backslash.
            return "\"" + Regex.Replace(argument, "(\\\\*)\"", "$1$1\\\"").TrimEnd('\0').Replace("\r", "").Replace("\n", "") + new string('\\', TrailingBackslashes(argument)) + "\"";
        }
        private static int TrailingBackslashes(string value) { int n = 0; for (int i = value.Length - 1; i >= 0 && value[i] == '\\'; --i) ++n; return n; }
        private static string WslPath() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "wsl.exe"); }
        private static ProcessStartInfo WslInfo(string arguments) {
            return new ProcessStartInfo(WslPath(), arguments) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        }
        private async Task<string> ConvertPathAsync() {
            using (var child = Process.Start(WslInfo("--exec wslpath -u " + Quote(Path.Combine(root, "desktop_bridge.py"))))) {
                var output = child.StandardOutput.ReadToEndAsync();
                var errors = child.StandardError.ReadToEndAsync();
                if (await Task.WhenAny(output, Task.Delay(20000)) != output) { child.Kill(); throw new InvalidOperationException("WSL non risponde. Completa la configurazione della distribuzione Linux e riprova."); }
                await Task.Run(() => child.WaitForExit()); await errors;
                string path = (await output).Trim();
                if (child.ExitCode != 0 || !path.StartsWith("/") || path.Contains("\n") || path.Length > 4096)
                    throw new InvalidOperationException("Installa e avvia una distribuzione WSL 2 con Python 3.11+ e python3-venv. La guida spiega i passaggi.");
                return path;
            }
        }

        private async Task StartAsync() {
            if (busy || closing) return;
            busy = true; start.Enabled = false; progress.Visible = true;
            try {
                CoreWebView2Environment.GetAvailableBrowserVersionString();
                status.Text = "Preparazione del motore Linux…";
                string path = await ConvertPathAsync();
                if (closing) return;
                bridge = Process.Start(WslInfo("--exec python3 -I " + Quote(path)));
                // Consume stderr without exposing it in UI or writing credentials.
                var stderr = bridge.StandardError.ReadToEndAsync();
                bool ready = false;
                while (!closing) {
                    string line = await bridge.StandardOutput.ReadLineAsync();
                    if (line == null) break;
                    if (line.Length > 8192) throw new InvalidOperationException("Risposta del motore non valida.");
                    var message = json.Deserialize<Dictionary<string, object>>(line);
                    string kind = Convert.ToString(message["kind"]);
                    if (kind == "progress") status.Text = Convert.ToString(message["message"]);
                    else if (kind == "error") throw new InvalidOperationException(Convert.ToString(message["message"]));
                    else if (kind == "ready" && !ready) {
                        string token = Convert.ToString(message["token"]);
                        origin = Convert.ToString(message["url"]);
                        await VerifyWindowsListenerAsync(origin, token);
                        await ShowDashboardAsync(origin, token);
                        ready = true;
                    }
                }
                await stderr;
                if (!closing) throw new InvalidOperationException("Il motore si è chiuso. Puoi riaprirlo senza perdere i risultati salvati.");
            } catch (WebView2RuntimeNotFoundException) {
                ShowFailure("Installa Microsoft Edge WebView2 Runtime, poi riapri Cheker. Trovi il collegamento nella guida.");
            } catch (Exception ex) {
                if (!closing) ShowFailure(ex is InvalidOperationException ? ex.Message : "Avvio non riuscito. Consulta la guida e i log nella cartella del programma.");
            }
            if (!closing) { await StopBridgeAsync(); busy = false; start.Enabled = true; progress.Visible = false; }
        }

        private async Task VerifyWindowsListenerAsync(string address, string token) {
            Uri uri;
            if (!Uri.TryCreate(address, UriKind.Absolute, out uri) || uri.Scheme != "http" || uri.Host != "127.0.0.1" || uri.AbsolutePath != "/" || uri.Query != "" || uri.Fragment != "" || uri.UserInfo != "" || !Regex.IsMatch(token, "^[A-Za-z0-9_-]{32,256}$"))
                throw new InvalidOperationException("L'indirizzo del motore non è verificabile.");
            using (var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false })
            using (var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2), MaxResponseContentBufferSize = 4096 }) {
                for (int attempt = 0; attempt < 20; ++attempt) {
                    byte[] challenge = new byte[32]; using (var random = RandomNumberGenerator.Create()) random.GetBytes(challenge);
                    string nonce = Hex(challenge);
                    try {
                        var response = await client.GetAsync(address + "/api/health?nonce=" + nonce);
                        if (!response.IsSuccessStatusCode) throw new InvalidOperationException("Il servizio locale non ha superato la verifica d'identità.");
                        var body = json.Deserialize<Dictionary<string, object>>(await response.Content.ReadAsStringAsync());
                        string expected;
                        using (var hmac = new HMACSHA256(Encoding.ASCII.GetBytes(token)))
                            expected = Hex(hmac.ComputeHash(Encoding.ASCII.GetBytes("mcp-integrity-guard-health-v2\0" + "127.0.0.1\0" + uri.Port + "\0" + nonce)));
                        object received;
                        if (!body.TryGetValue("proof", out received) || !FixedEquals(expected, Convert.ToString(received)))
                            throw new InvalidOperationException("Il servizio locale non ha superato la verifica d'identità.");
                        return;
                    } catch (HttpRequestException) { if (attempt == 19) break; }
                    catch (TaskCanceledException) { if (attempt == 19) break; }
                    await Task.Delay(500);
                }
            }
            throw new InvalidOperationException("Windows non raggiunge il motore WSL. Verifica il collegamento localhost nella guida.");
        }
        private static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
        private static bool FixedEquals(string a, string b) { if (a.Length != b.Length) return false; int d = 0; for (int i = 0; i < a.Length; ++i) d |= a[i] ^ b[i]; return d == 0; }
        private bool LocalUri(string address) { Uri uri; return Uri.TryCreate(address, UriKind.Absolute, out uri) && uri.GetLeftPart(UriPartial.Authority) == origin && uri.UserInfo == ""; }

        private async Task ShowDashboardAsync(string address, string token) {
            status.Text = "Collegamento verificato · documenti elaborati su questo dispositivo";
            if (view.CoreWebView2 == null) {
                var environment = await CoreWebView2Environment.CreateAsync(null, Path.Combine(root, "profilo-interfaccia"));
                await view.EnsureCoreWebView2Async(environment);
                view.CoreWebView2.Settings.AreDevToolsEnabled = false;
                view.CoreWebView2.Settings.AreHostObjectsAllowed = false;
                view.CoreWebView2.Settings.IsWebMessageEnabled = false;
                view.CoreWebView2.Settings.IsStatusBarEnabled = false;
                view.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
                view.CoreWebView2.NavigationStarting += (sender, args) => { if (!LocalUri(args.Uri)) args.Cancel = true; };
                view.CoreWebView2.NewWindowRequested += (sender, args) => { args.Handled = true; };
                view.CoreWebView2.PermissionRequested += (sender, args) => { args.State = CoreWebView2PermissionState.Deny; };
                view.CoreWebView2.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
                view.CoreWebView2.WebResourceRequested += (sender, args) => {
                    if (!LocalUri(args.Request.Uri)) args.Response = environment.CreateWebResourceResponse(Stream.Null, 403, "Blocked", "Content-Type: text/plain");
                };
            }
            await view.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync("if(window.top===window && location.origin===" + json.Serialize(address) + "){sessionStorage.setItem('mcp-integrity-guard-token'," + json.Serialize(token) + ");}");
            view.CoreWebView2.Navigate(address + "/");
            welcome.Visible = false; view.Visible = true; progress.Visible = false;
        }

        private void ShowFailure(string message) { status.Text = "Avvio da completare"; detail.Text = message; welcome.Visible = true; view.Visible = false; start.Text = "Riprova"; }
        private async Task StopBridgeAsync() {
            var process = bridge;
            if (process == null) return;
            bridge = null;
            try {
                if (!process.HasExited) { await process.StandardInput.WriteLineAsync("STOP"); process.StandardInput.Close(); await Task.Run(() => process.WaitForExit(25000)); }
            } catch (InvalidOperationException) { } catch (IOException) { }
            finally { process.Dispose(); }
        }
        private async void CloseAsync(object sender, FormClosingEventArgs args) {
            if (closing) return;
            args.Cancel = true; closing = true; status.Text = "Chiudo il motore e salvo lo stato…"; Enabled = false;
            await StopBridgeAsync(); view.Dispose(); Close();
        }
    }
}
