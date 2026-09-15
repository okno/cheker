using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("Cheker - Installazione")]
[assembly: AssemblyProduct("Cheker")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: TargetFramework(".NETFramework,Version=v4.8")]

namespace ChekerSetup
{
    public sealed class SetupFailure : Exception
    {
        public readonly string Code;
        public SetupFailure(string code, string message) : base(message) { Code = code; }
    }

    public sealed class InstallResult
    {
        public string DirectoryPath { get; internal set; }
        public bool AlreadyInstalled { get; internal set; }
        public int FilesVerified { get; internal set; }
    }

    // This API installs only the authenticated embedded package. It never starts Cheker.
    public static class PackageInstaller
    {
        public const string ZipSha256 = "b626390c9e169d48706a096e83743b5b81eea8df2370c6a5c83d1690db46fb81";
        public const string VersionFolder = "Cheker-XLSX-anteprima-4-b626390c9e16";
        const string ZipRoot = "cheker-windows-anteprima-4/";
        const string ResourceName = "Cheker.Payload.zip";
        const int MaxEntries = 256, MaxZipBytes = 16 * 1024 * 1024;
        const long MaxFileBytes = 16 * 1024 * 1024, MaxExpandedBytes = 64 * 1024 * 1024;

        sealed class Package : IDisposable
        {
            internal readonly MemoryStream Bytes;
            internal readonly ZipArchive Archive;
            internal readonly Dictionary<string, ZipArchiveEntry> Entries;
            internal readonly Dictionary<string, string> Hashes;
            internal Package(MemoryStream bytes, ZipArchive archive,
                Dictionary<string, ZipArchiveEntry> entries, Dictionary<string, string> hashes)
            { Bytes = bytes; Archive = archive; Entries = entries; Hashes = hashes; }
            public void Dispose() { Archive.Dispose(); Bytes.Dispose(); }
        }

        static void Need(bool condition, string code, string message)
        { if (!condition) throw new SetupFailure(code, message); }

        static string Hash(Stream stream)
        { using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant(); }

        static string HashFile(string path)
        { using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) return Hash(input); }

        static string ValidateRelative(string name)
        {
            Need(!String.IsNullOrEmpty(name) && name.Length <= 200 && !name.Contains("\\") && !name.Contains(":"),
                "PACKAGE_PATH", "Il pacchetto contiene un percorso non consentito.");
            var parts = name.Split('/');
            foreach (string part in parts)
            {
                Need(part.Length > 0 && part.Length <= 120 && part != "." && part != ".." &&
                    !part.EndsWith(".", StringComparison.Ordinal) && !part.EndsWith(" ", StringComparison.Ordinal) &&
                    part.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 && !part.Any(Char.IsControl),
                    "PACKAGE_PATH", "Il pacchetto contiene un nome di file non consentito.");
                string stem = part.Split('.')[0].ToUpperInvariant();
                Need(stem != "CON" && stem != "PRN" && stem != "AUX" && stem != "NUL" &&
                    !(stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) &&
                      stem[3] >= '1' && stem[3] <= '9'), "PACKAGE_PATH", "Il pacchetto contiene un nome riservato.");
            }
            return name;
        }

        static Dictionary<string, ZipArchiveEntry> ValidateEntries(ZipArchive archive)
        {
            Need(archive.Entries.Count > 0 && archive.Entries.Count <= MaxEntries,
                "PACKAGE_LIMIT", "Il pacchetto supera il limite di file consentito.");
            var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
            long total = 0;
            foreach (var entry in archive.Entries)
            {
                Need(entry.FullName.StartsWith(ZipRoot, StringComparison.Ordinal), "PACKAGE_ROOT", "La struttura del pacchetto non è valida.");
                string relative = ValidateRelative(entry.FullName.Substring(ZipRoot.Length));
                int unixType = (entry.ExternalAttributes >> 16) & 0xF000;
                Need((unixType == 0 || unixType == 0x8000) && (entry.ExternalAttributes & 0x410) == 0,
                    "PACKAGE_FILE_TYPE", "Il pacchetto contiene un collegamento o un tipo di file non consentito.");
                Need(entry.Length >= 0 && entry.Length <= MaxFileBytes &&
                    entry.Length <= Math.Max(1L, entry.CompressedLength) * 250,
                    "PACKAGE_LIMIT", "Un file del pacchetto supera i limiti consentiti.");
                total = checked(total + entry.Length);
                Need(total <= MaxExpandedBytes, "PACKAGE_LIMIT", "Il pacchetto estratto è troppo grande.");
                Need(!entries.ContainsKey(relative), "PACKAGE_DUPLICATE", "Il pacchetto contiene nomi duplicati.");
                entries.Add(relative, entry);
            }
            foreach (string name in entries.Keys)
            {
                int slash = name.LastIndexOf('/');
                while (slash >= 0)
                {
                    Need(!entries.ContainsKey(name.Substring(0, slash)), "PACKAGE_COLLISION", "La struttura del pacchetto contiene nomi incompatibili.");
                    slash = name.LastIndexOf('/', slash - 1);
                }
            }
            return entries;
        }

        static byte[] ReadBounded(Stream input, long limit)
        {
            using (var output = new MemoryStream())
            {
                var buffer = new byte[65536]; int count;
                while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
                {
                    Need(output.Length + count <= limit, "PACKAGE_LIMIT", "Il pacchetto supera i limiti consentiti.");
                    output.Write(buffer, 0, count);
                }
                return output.ToArray();
            }
        }

        static Package OpenPackage()
        {
            byte[] bytes;
            using (Stream embedded = typeof(PackageInstaller).Assembly.GetManifestResourceStream(ResourceName))
            {
                Need(embedded != null, "PACKAGE_MISSING", "Il pacchetto incorporato non è disponibile.");
                bytes = ReadBounded(embedded, MaxZipBytes);
            }
            var memory = new MemoryStream(bytes, false);
            Need(Hash(memory) == ZipSha256, "PACKAGE_HASH", "L'installer è incompleto o modificato. Usa una copia verificata.");
            memory.Position = 0;
            ZipArchive archive = null;
            try
            {
                archive = new ZipArchive(memory, ZipArchiveMode.Read, true);
                var entries = ValidateEntries(archive);
                Need(entries.Count == 42 && entries.ContainsKey("MANIFEST-WINDOWS.json"), "PACKAGE_MANIFEST", "Il manifesto del pacchetto non è completo.");
                byte[] manifest;
                using (var input = entries["MANIFEST-WINDOWS.json"].Open()) manifest = ReadBounded(input, 256 * 1024);
                var serializer = new JavaScriptSerializer { MaxJsonLength = 256 * 1024, RecursionLimit = 16 };
                var document = serializer.DeserializeObject(Encoding.UTF8.GetString(manifest)) as Dictionary<string, object>;
                Need(document != null && document.ContainsKey("sha256"), "PACKAGE_MANIFEST", "Il manifesto del pacchetto non è valido.");
                var listed = document["sha256"] as Dictionary<string, object>;
                Need(listed != null && listed.Count == entries.Count - 1, "PACKAGE_MANIFEST", "Il manifesto del pacchetto non copre tutti i file.");
                var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var item in listed)
                {
                    string name = ValidateRelative(item.Key); string expected = item.Value as string;
                    Need(entries.ContainsKey(name) && name != "MANIFEST-WINDOWS.json" && expected != null &&
                        expected.Length == 64 && expected.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) &&
                        !hashes.ContainsKey(name), "PACKAGE_MANIFEST", "Il manifesto del pacchetto contiene una voce non valida.");
                    hashes.Add(name, expected);
                }
                using (var raw = new MemoryStream(manifest, false)) hashes.Add("MANIFEST-WINDOWS.json", Hash(raw));
                Need(entries.Keys.All(hashes.ContainsKey), "PACKAGE_MANIFEST", "Il manifesto del pacchetto non è completo.");
                return new Package(memory, archive, entries, hashes);
            }
            catch { if (archive != null) archive.Dispose(); memory.Dispose(); throw; }
        }

        static bool Exists(string path) { return File.Exists(path) || Directory.Exists(path); }

        static void CheckAncestors(string path)
        {
            string current = Path.GetFullPath(path);
            while (!String.IsNullOrEmpty(current))
            {
                if (Exists(current)) Need((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0,
                    "DESTINATION_LINK", "Scegli una cartella locale senza collegamenti o junction.");
                string parent = Path.GetDirectoryName(current.TrimEnd(Path.DirectorySeparatorChar));
                if (parent == current || String.IsNullOrEmpty(parent)) break;
                current = parent;
            }
        }

        static string ParentDirectory(string value)
        {
            Need(!String.IsNullOrWhiteSpace(value) && !value.StartsWith(@"\\", StringComparison.Ordinal),
                "DESTINATION_PATH", "Scegli una cartella su un disco locale.");
            string path = Path.GetFullPath(value);
            Need(path.Length >= 3 && Char.IsLetter(path[0]) && path[1] == ':' && path[2] == '\\' &&
                !path.Substring(2).Contains(":"), "DESTINATION_PATH", "Scegli una cartella su un disco locale.");
            CheckAncestors(path);
            Need(!File.Exists(path), "DESTINATION_FILE", "Il percorso scelto è un file. Scegli una cartella.");
            return path.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        }

        static string Destination(string directory, string relative)
        {
            ValidateRelative(relative);
            string root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string full = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
            Need(full.StartsWith(root, StringComparison.OrdinalIgnoreCase) && full.Length <= 240,
                "DESTINATION_LENGTH", "Il percorso è troppo lungo. Scegli una cartella più vicina alla radice del disco.");
            return full;
        }

        static int VerifyDirectory(string directory, Package package)
        {
            CheckAncestors(directory);
            Need(Directory.Exists(directory), "INSTALLED_MISSING", "La cartella della versione non è disponibile.");
            foreach (var item in package.Hashes)
            {
                string file = Destination(directory, item.Key);
                CheckAncestors(file);
                Need(File.Exists(file) && (File.GetAttributes(file) & FileAttributes.Directory) == 0 &&
                    new FileInfo(file).Length == package.Entries[item.Key].Length && HashFile(file) == item.Value,
                    "INSTALLED_CHANGED", "La cartella della versione esiste ma i file non coincidono. Non è stata sovrascritta. Scegli un'altra destinazione.");
            }
            return package.Hashes.Count;
        }

        internal static Image ReadLogo()
        {
            using (var package = OpenPackage())
            using (var input = package.Entries["cheker.png"].Open())
            {
                byte[] bytes = ReadBounded(input, MaxFileBytes);
                using (var raw = new MemoryStream(bytes, false))
                {
                    Need(Hash(raw) == package.Hashes["cheker.png"], "PACKAGE_FILE_HASH", "Il logo incorporato non è valido.");
                    raw.Position = 0;
                    using (var image = Image.FromStream(raw, true, true)) return new Bitmap(image, new Size(56, 56));
                }
            }
        }

        public static int Verify(string directory)
        { using (var package = OpenPackage()) return VerifyDirectory(directory, package); }

        static void EnsureOwnDirectories(string stage, string directory, List<string> created)
        {
            if (Directory.Exists(directory)) { CheckAncestors(directory); return; }
            Need(directory.StartsWith(stage + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase),
                "STAGING_PATH", "La cartella temporanea non è valida.");
            EnsureOwnDirectories(stage, Path.GetDirectoryName(directory), created);
            Directory.CreateDirectory(directory); created.Add(directory); CheckAncestors(directory);
        }

        static void CleanupOwnStage(string stage, List<string> files, List<string> directories)
        {
            // Never recurse into unknown content, a replacement junction, or an older stage.
            try
            {
                CheckAncestors(stage);
                for (int i = files.Count - 1; i >= 0; i--)
                { CheckAncestors(files[i]); if (File.Exists(files[i])) File.Delete(files[i]); }
                for (int i = directories.Count - 1; i >= 0; i--)
                { CheckAncestors(directories[i]); if (Directory.Exists(directories[i])) Directory.Delete(directories[i], false); }
            }
            catch { /* Preserve anything uncertain for manual inspection; never broaden cleanup. */ }
        }

        public static InstallResult Install(string parentDirectory, Action<int, string> progress)
        {
            if (progress == null) progress = delegate { };
            progress(5, "Verifica dell'installer…");
            using (var package = OpenPackage())
            {
                string parent = ParentDirectory(parentDirectory);
                string final = Path.Combine(parent, VersionFolder);
                foreach (string name in package.Entries.Keys) Destination(final, name);
                if (Exists(final))
                    return new InstallResult { DirectoryPath = final, AlreadyInstalled = true, FilesVerified = VerifyDirectory(final, package) };
                Directory.CreateDirectory(parent); CheckAncestors(parent);
                string stage = Path.Combine(parent, ".Cheker-setup-" + Guid.NewGuid().ToString("N"));
                Need(!Exists(stage), "STAGING_EXISTS", "La cartella temporanea è già presente. Riprova.");
                var files = new List<string>(); var directories = new List<string>();
                Directory.CreateDirectory(stage); directories.Add(stage);
                bool moved = false;
                try
                {
                    CheckAncestors(stage);
                    int done = 0;
                    foreach (var item in package.Entries)
                    {
                        string target = Destination(stage, item.Key);
                        EnsureOwnDirectories(stage, Path.GetDirectoryName(target), directories);
                        using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            files.Add(target);
                            using (var input = item.Value.Open())
                            {
                                long total = 0; var buffer = new byte[65536]; int count;
                                while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
                                {
                                    total += count;
                                    Need(total <= item.Value.Length && total <= MaxFileBytes, "PACKAGE_LIMIT", "Un file estratto supera il limite previsto.");
                                    output.Write(buffer, 0, count);
                                }
                                Need(total == item.Value.Length, "PACKAGE_TRUNCATED", "Il pacchetto è incompleto.");
                            }
                            output.Flush(true);
                        }
                        Need(HashFile(target) == package.Hashes[item.Key], "PACKAGE_FILE_HASH", "La verifica di un file estratto non è riuscita.");
                        done++; progress(10 + done * 70 / package.Entries.Count, "Installazione dei file… " + done + "/" + package.Entries.Count);
                    }
                    VerifyDirectory(stage, package);
                    CheckAncestors(parent);
                    Need(!Exists(final), "DESTINATION_EXISTS", "La cartella della versione è stata creata nel frattempo. Non è stata sovrascritta.");
                    Directory.Move(stage, final); moved = true;
                    int verified = VerifyDirectory(final, package);
                    progress(100, "Installazione verificata.");
                    return new InstallResult { DirectoryPath = final, AlreadyInstalled = false, FilesVerified = verified };
                }
                finally { if (!moved) CleanupOwnStage(stage, files, directories); }
            }
        }
    }

    public sealed class SetupForm : Form
    {
        readonly TextBox destination = new TextBox();
        readonly TextBox status = new TextBox();
        readonly ProgressBar progress = new ProgressBar();
        readonly Button install = new Button();
        readonly Button browse = new Button();
        readonly Button open = new Button();
        bool busy;
        string installedDirectory;

        public SetupForm()
        {
            Text = "Installa Cheker"; StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(670, 430); MinimumSize = new Size(660, 460);
            Font = new Font("Segoe UI", 10F); BackColor = Color.White;
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 2, RowCount = 8 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            var title = new Label { Text = "Cheker", AutoSize = true, Font = new Font("Segoe UI", 25F, FontStyle.Bold), ForeColor = Color.FromArgb(20, 85, 89) };
            var logo = new PictureBox { Image = PackageInstaller.ReadLogo(), Size = new Size(56, 56), SizeMode = PictureBoxSizeMode.Zoom, AccessibleName = "Logo Cheker", Margin = new Padding(0, 0, 12, 0) };
            Disposed += delegate { logo.Image.Dispose(); };
            var heading = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false };
            heading.Controls.Add(logo); heading.Controls.Add(title);
            layout.Controls.Add(heading, 0, 0); layout.SetColumnSpan(heading, 2);
            var subtitle = new Label { Text = "Anteprima XLSX · Installazione per questo utente", AutoSize = true, Margin = new Padding(0, 5, 0, 12) };
            layout.Controls.Add(subtitle, 0, 1); layout.SetColumnSpan(subtitle, 2);
            var hint = new Label { Text = "Scegli dove creare la nuova cartella di Cheker.\nI dati e le versioni già presenti vengono conservati.", AutoSize = true, Margin = new Padding(0, 0, 0, 12) };
            layout.Controls.Add(hint, 0, 2); layout.SetColumnSpan(hint, 2);
            destination.Text = Directory.Exists(@"D:\") ? @"D:\Cheker\app\windows" : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Cheker", "app", "windows");
            destination.Dock = DockStyle.Fill; destination.AccessibleName = "Cartella di destinazione";
            browse.Text = "Sfoglia…"; browse.Dock = DockStyle.Fill;
            browse.Click += delegate { using (var dialog = new FolderBrowserDialog { Description = "Scegli dove installare la nuova versione di Cheker", SelectedPath = destination.Text }) if (dialog.ShowDialog(this) == DialogResult.OK) destination.Text = dialog.SelectedPath; };
            layout.Controls.Add(destination, 0, 3); layout.Controls.Add(browse, 1, 3);
            var requirements = new Label { Text = "Il motore usa WSL2 e Python 3.11+ con venv;\nla finestra richiede WebView2.\nQuesto installer non installa automaticamente i prerequisiti.", AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(0, 12, 0, 12) };
            layout.Controls.Add(requirements, 0, 4); layout.SetColumnSpan(requirements, 2);
            progress.Dock = DockStyle.Fill; layout.Controls.Add(progress, 0, 5); layout.SetColumnSpan(progress, 2);
            status.Multiline = true; status.ReadOnly = true; status.BorderStyle = BorderStyle.None; status.BackColor = Color.White;
            status.Text = "Pronto. Non sono richiesti privilegi amministratore."; status.Dock = DockStyle.Fill;
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            layout.Controls.Add(status, 0, 6); layout.SetColumnSpan(status, 2);
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
            install.Text = "Installa e avvia"; install.Width = 170; install.Height = 38; install.BackColor = Color.FromArgb(20, 85, 89); install.ForeColor = Color.White; install.FlatStyle = FlatStyle.Flat;
            install.Click += InstallClicked;
            open.Text = "Apri cartella"; open.Width = 125; open.Height = 38; open.Enabled = false;
            open.Click += delegate { if (installedDirectory != null) Process.Start(new ProcessStartInfo(installedDirectory) { UseShellExecute = true }); };
            buttons.Controls.Add(install); buttons.Controls.Add(open); layout.Controls.Add(buttons, 0, 7); layout.SetColumnSpan(buttons, 2);
            Controls.Add(layout); AcceptButton = install;
            FormClosing += delegate(object sender, FormClosingEventArgs e) { if (busy) { e.Cancel = true; status.Text = "Attendi il completamento della verifica e dell'installazione."; } };
        }

        async void InstallClicked(object sender, EventArgs e)
        {
            if (busy) return;
            busy = true; install.Enabled = browse.Enabled = destination.Enabled = open.Enabled = false;
            try
            {
                string selected = destination.Text;
                InstallResult result = await Task.Run(() => PackageInstaller.Install(selected, (value, message) =>
                    BeginInvoke((Action)(() => { progress.Value = value; status.Text = message; }))));
                installedDirectory = result.DirectoryPath;
                status.Text = (result.AlreadyInstalled ? "Versione già presente, tutti i file verificati.\r\n" : "Installazione completata e verificata.\r\n") + installedDirectory;
                Process.Start(new ProcessStartInfo(Path.Combine(installedDirectory, "Cheker.exe")) { WorkingDirectory = installedDirectory, UseShellExecute = false });
                status.AppendText("\r\nCheker è stato avviato."); progress.Value = 100; install.Text = "Verifica e avvia";
            }
            catch (SetupFailure error) { status.Text = error.Message + "\r\nCodice: " + error.Code; }
            catch (UnauthorizedAccessException) { status.Text = "Non puoi scrivere nella cartella scelta. Seleziona una cartella del tuo utente."; }
            catch (PathTooLongException) { status.Text = "Il percorso è troppo lungo. Scegli una cartella più vicina alla radice del disco."; }
            catch (Exception)
            { status.Text = installedDirectory == null ? "Installazione non completata. Verifica lo spazio libero e i permessi oppure scegli un'altra cartella." : "I file sono installati, ma Cheker non è stato avviato. Apri la cartella e consulta LEGGIMI.html."; }
            finally { busy = false; install.Enabled = browse.Enabled = destination.Enabled = true; open.Enabled = installedDirectory != null; }
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            try { Application.Run(new SetupForm()); }
            catch (SetupFailure error) { MessageBox.Show(error.Message + "\r\nCodice: " + error.Code, "Impossibile aprire l'installer", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            catch (Exception) { MessageBox.Show("L'installer non può essere aperto. Usa una copia verificata e controlla che .NET Framework 4.8 sia disponibile.", "Installazione Cheker", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }
    }
}
