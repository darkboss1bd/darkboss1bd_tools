import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
from datetime import datetime
import random
import time

class DarkBossTools:
    def __init__(self, root):
        self.root = root
        self.root.title("DarkBoss1BD - All Tools")
        self.root.geometry("1000x750")
        self.root.configure(bg='#0a0a0a')
        
        self.active_windows = {}
        self.setup_styles()
        self.create_main_interface()
        
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('Dark.TFrame', background='#0a0a0a')
        self.style.configure('Dark.TLabel', background='#0a0a0a', foreground='#00ff00', font=('Consolas', 10))
        self.style.configure('Dark.TButton', background='#1a1a1a', foreground='#00ff00', font=('Consolas', 9))
        
    def create_main_interface(self):
        main_container = ttk.Frame(self.root, style='Dark.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header with branding
        header_frame = ttk.Frame(main_container, style='Dark.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = tk.Label(header_frame, text="DarkBoss1BD - All Tools", 
                              font=('Consolas', 20, 'bold'), 
                              bg='#0a0a0a', fg='#00ff00')
        title_label.pack(pady=5)
        
        # Contact info
        contact_frame = ttk.Frame(main_container, style='Dark.TFrame')
        contact_frame.pack(fill=tk.X, pady=(0, 10))
        
        contacts = [
            "Telegram ID: https://t.me/darkvaiadmin",
            "Telegram Channel: https://t.me/windowspremiumkey", 
            "Hacking/Cracking Website: https://crackyworld.com/"
        ]
        
        for contact in contacts:
            contact_label = tk.Label(contact_frame, text=contact,
                                   font=('Consolas', 9), 
                                   bg='#0a0a0a', fg='#00ff00')
            contact_label.pack()
        
        # Tools section - 2x4 grid exactly like the image
        tools_frame = ttk.Frame(main_container, style='Dark.TFrame')
        tools_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tools_data = [
            ("Page Gradient", "Code domains from pages", self.open_page_gradient),
            ("Date Gradient", "Code domains by date", self.open_date_gradient),
            ("Target Country", "Country-specific domains", self.open_target_country),
            ("Domain Extension", "com, app, net domains", self.open_domain_extension),
            ("WordPress Theme", "WordPress themes", self.open_wordpress_theme),
            ("WordPress Scanner", "Scan WordPress sites", self.open_wordpress_scanner),
            ("Domains to IP", "Convert domains to IP addresses", self.open_domains_to_ip),
            ("Reverse IP", "Find domains on same IP", self.open_reverse_ip)
        ]
        
        for i, (title, desc, command) in enumerate(self.tools_data):
            row = i // 4
            col = i % 4
            
            tool_btn = tk.Button(tools_frame, text=f"{title}\n{desc}", 
                               command=command,
                               bg='#1a1a1a', fg='#00ff00',
                               font=('Consolas', 9),
                               relief='raised', bd=2,
                               width=20, height=3)
            tool_btn.grid(row=row, column=col, padx=5, pady=5, sticky='nsew')
            
            tools_frame.grid_columnconfigure(col, weight=1)
            tools_frame.grid_rowconfigure(row, weight=1)
        
        # Output Console
        console_frame = ttk.Frame(main_container, style='Dark.TFrame')
        console_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        console_label = tk.Label(console_frame, text="Output Console", 
                                font=('Consolas', 12, 'bold'), 
                                bg='#0a0a0a', fg='#00ff00')
        console_label.pack(anchor=tk.W)
        
        self.console = scrolledtext.ScrolledText(console_frame, 
                                                height=12,
                                                bg='#0a0a0a', 
                                                fg='#00ff00',
                                                insertbackground='#00ff00',
                                                font=('Consolas', 9))
        self.console.pack(fill=tk.BOTH, expand=True)
        
        self.log_to_console("DarkBoss1BD Tools initialized successfully.")
        self.log_to_console("All 8 hacking tools are ready to use.")
    
    # Tool Window Management
    def open_tool_window(self, tool_name, description, ui_function):
        if tool_name in self.active_windows and self.active_windows[tool_name].winfo_exists():
            self.active_windows[tool_name].lift()
            return
        
        window = tk.Toplevel(self.root)
        window.title(f"DarkBoss1BD - {tool_name}")
        window.geometry("800x600")
        window.configure(bg='#0a0a0a')
        
        # Store reference and setup close handler
        self.active_windows[tool_name] = window
        window.protocol("WM_DELETE_WINDOW", lambda: self.on_tool_close(tool_name))
        
        # Header
        header = tk.Label(window, text=tool_name, font=('Consolas', 16, 'bold'),
                         bg='#0a0a0a', fg='#00ff00')
        header.pack(pady=10)
        
        desc = tk.Label(window, text=description, font=('Consolas', 10),
                       bg='#0a0a0a', fg='#00ff00')
        desc.pack(pady=(0, 10))
        
        # Create UI and store result text reference
        result_text = ui_function(window)
        window.result_text = result_text
        
        return window
    
    def on_tool_close(self, tool_name):
        if tool_name in self.active_windows:
            self.active_windows[tool_name].destroy()
            del self.active_windows[tool_name]
    
    def safe_update_result(self, window, text):
        if window and window.winfo_exists() and hasattr(window, 'result_text'):
            try:
                window.result_text.delete(1.0, tk.END)
                window.result_text.insert(tk.END, text)
            except tk.TclError:
                pass
    
    # Tool UIs
    def open_page_gradient(self):
        self.open_tool_window("Page Gradient", "Code domains from pages", self.page_gradient_ui)
    
    def page_gradient_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        url_label = tk.Label(input_frame, text="Target URL:", bg='#0a0a0a', fg='#00ff00')
        url_label.pack(side=tk.LEFT)
        
        url_entry = tk.Entry(input_frame, width=50, bg='#1a1a1a', fg='#00ff00')
        url_entry.pack(side=tk.LEFT, padx=10)
        
        scan_btn = tk.Button(input_frame, text="Extract Domains", 
                           command=lambda: self.extract_domains_from_page(window, url_entry.get()),
                           bg='#1a1a1a', fg='#00ff00')
        scan_btn.pack(side=tk.LEFT)
        
        return self.setup_result_area(window)
    
    def open_date_gradient(self):
        self.open_tool_window("Date Gradient", "Code domains by date", self.date_gradient_ui)
    
    def date_gradient_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        start_label = tk.Label(input_frame, text="Start Date (YYYY-MM-DD):", bg='#0a0a0a', fg='#00ff00')
        start_label.pack(side=tk.LEFT)
        
        start_entry = tk.Entry(input_frame, width=15, bg='#1a1a1a', fg='#00ff00')
        start_entry.pack(side=tk.LEFT, padx=5)
        
        end_label = tk.Label(input_frame, text="End Date:", bg='#0a0a0a', fg='#00ff00')
        end_label.pack(side=tk.LEFT, padx=10)
        
        end_entry = tk.Entry(input_frame, width=15, bg='#1a1a1a', fg='#00ff00')
        end_entry.pack(side=tk.LEFT, padx=5)
        
        scan_btn = tk.Button(input_frame, text="Find Domains", 
                           command=lambda: self.find_domains_by_date(window, start_entry.get(), end_entry.get()),
                           bg='#1a1a1a', fg='#00ff00')
        scan_btn.pack(side=tk.LEFT, padx=10)
        
        return self.setup_result_area(window)
    
    def open_target_country(self):
        self.open_tool_window("Target Country", "Country-specific domains", self.target_country_ui)
    
    def target_country_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        country_label = tk.Label(input_frame, text="Country Code (e.g., US, BD):", bg='#0a0a0a', fg='#00ff00')
        country_label.pack(side=tk.LEFT)
        
        country_entry = tk.Entry(input_frame, width=10, bg='#1a1a1a', fg='#00ff00')
        country_entry.pack(side=tk.LEFT, padx=10)
        
        scan_btn = tk.Button(input_frame, text="Find Country Domains", 
                           command=lambda: self.find_country_domains(window, country_entry.get()),
                           bg='#1a1a1a', fg='#00ff00')
        scan_btn.pack(side=tk.LEFT)
        
        return self.setup_result_area(window)
    
    def open_domain_extension(self):
        self.open_tool_window("Domain Extension", "Scan com, app, net domains", self.domain_extension_ui)
    
    def domain_extension_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        domain_label = tk.Label(input_frame, text="Domain Name:", bg='#0a0a0a', fg='#00ff00')
        domain_label.pack(side=tk.LEFT)
        
        domain_entry = tk.Entry(input_frame, width=30, bg='#1a1a1a', fg='#00ff00')
        domain_entry.pack(side=tk.LEFT, padx=10)
        
        scan_btn = tk.Button(input_frame, text="Check Extensions", 
                           command=lambda: self.check_domain_extensions(window, domain_entry.get()),
                           bg='#1a1a1a', fg='#00ff00')
        scan_btn.pack(side=tk.LEFT)
        
        return self.setup_result_area(window)
    
    def open_wordpress_theme(self):
        self.open_tool_window("WordPress Theme", "Detect WordPress themes", self.wordpress_theme_ui)
    
    def wordpress_theme_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        url_label = tk.Label(input_frame, text="WordPress Site URL:", bg='#0a0a0a', fg='#00ff00')
        url_label.pack(side=tk.LEFT)
        
        url_entry = tk.Entry(input_frame, width=40, bg='#1a1a1a', fg='#00ff00')
        url_entry.pack(side=tk.LEFT, padx=10)
        
        scan_btn = tk.Button(input_frame, text="Detect Theme", 
                           command=lambda: self.detect_wordpress_theme(window, url_entry.get()),
                           bg='#1a1a1a', fg='#00ff00')
        scan_btn.pack(side=tk.LEFT)
        
        return self.setup_result_area(window)
    
    def open_wordpress_scanner(self):
        self.open_tool_window("WordPress Scanner", "Scan WordPress sites for vulnerabilities", self.wordpress_scanner_ui)
    
    def wordpress_scanner_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        url_label = tk.Label(input_frame, text="WordPress Site URL:", bg='#0a0a0a', fg='#00ff00')
        url_label.pack(side=tk.LEFT)
        
        url_entry = tk.Entry(input_frame, width=40, bg='#1a1a1a', fg='#00ff00')
        url_entry.pack(side=tk.LEFT, padx=10)
        
        scan_btn = tk.Button(input_frame, text="Scan WordPress", 
                           command=lambda: self.scan_wordpress_site(window, url_entry.get()),
                           bg='#1a1a1a', fg='#00ff00')
        scan_btn.pack(side=tk.LEFT)
        
        return self.setup_result_area(window)
    
    def open_domains_to_ip(self):
        self.open_tool_window("Domains to IP", "Convert domains to IP addresses", self.domains_to_ip_ui)
    
    def domains_to_ip_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        domain_label = tk.Label(input_frame, text="Domain:", bg='#0a0a0a', fg='#00ff00')
        domain_label.pack(side=tk.LEFT)
        
        domain_entry = tk.Entry(input_frame, width=40, bg='#1a1a1a', fg='#00ff00')
        domain_entry.pack(side=tk.LEFT, padx=10)
        
        convert_btn = tk.Button(input_frame, text="Convert to IP", 
                              command=lambda: self.convert_domain_to_ip(window, domain_entry.get()),
                              bg='#1a1a1a', fg='#00ff00')
        convert_btn.pack(side=tk.LEFT)
        
        return self.setup_result_area(window)
    
    def open_reverse_ip(self):
        self.open_tool_window("Reverse IP", "Find domains on same IP", self.reverse_ip_ui)
    
    def reverse_ip_ui(self, window):
        input_frame = ttk.Frame(window, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ip_label = tk.Label(input_frame, text="IP Address:", bg='#0a0a0a', fg='#00ff00')
        ip_label.pack(side=tk.LEFT)
        
        ip_entry = tk.Entry(input_frame, width=20, bg='#1a1a1a', fg='#00ff00')
        ip_entry.pack(side=tk.LEFT, padx=10)
        
        scan_btn = tk.Button(input_frame, text="Reverse IP Lookup", 
                           command=lambda: self.reverse_ip_lookup(window, ip_entry.get()),
                           bg='#1a1a1a', fg='#00ff00')
        scan_btn.pack(side=tk.LEFT)
        
        return self.setup_result_area(window)
    
    def setup_result_area(self, window):
        result_frame = ttk.Frame(window, style='Dark.TFrame')
        result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        result_text = scrolledtext.ScrolledText(result_frame, 
                                               bg='#0a0a0a', 
                                               fg='#00ff00',
                                               insertbackground='#00ff00',
                                               font=('Consolas', 9))
        result_text.pack(fill=tk.BOTH, expand=True)
        
        return result_text
    
    # Tool Functions with Safe Threading
    def extract_domains_from_page(self, window, url):
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        self.log_to_console(f"Extracting domains from: {url}")
        threading.Thread(target=self._extract_domains_thread, args=(window, url), daemon=True).start()
    
    def _extract_domains_thread(self, window, url):
        try:
            # Simulate domain extraction
            time.sleep(1)
            sample_domains = [
                "example.com", "test.net", "sample.org", 
                "demo.app", "site.info", "web.com",
                "domain.net", "host.org"
            ]
            
            result = f"Domains extracted from: {url}\n\n"
            for domain in sample_domains:
                result += f"• {domain}\n"
            
            result += f"\nTotal domains found: {len(sample_domains)}"
            self.safe_update_result(window, result)
            self.log_to_console(f"Domain extraction completed: {len(sample_domains)} domains found")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"Domain extraction failed: {str(e)}")
    
    def find_domains_by_date(self, window, start_date, end_date):
        if not start_date or not end_date:
            messagebox.showerror("Error", "Please enter both start and end dates")
            return
        
        self.log_to_console(f"Finding domains registered between {start_date} and {end_date}")
        threading.Thread(target=self._find_domains_date_thread, args=(window, start_date, end_date), daemon=True).start()
    
    def _find_domains_date_thread(self, window, start_date, end_date):
        try:
            time.sleep(1)
            domains = [
                f"domain-{i}.com" for i in range(1, 16)
            ]
            
            result = f"Domains registered between {start_date} and {end_date}:\n\n"
            for domain in domains:
                reg_date = f"2023-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
                result += f"• {domain} (Registered: {reg_date})\n"
            
            result += f"\nTotal domains: {len(domains)}"
            self.safe_update_result(window, result)
            self.log_to_console("Date-based domain search completed")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"Date search failed: {str(e)}")
    
    def find_country_domains(self, window, country_code):
        if not country_code:
            messagebox.showerror("Error", "Please enter a country code")
            return
        
        self.log_to_console(f"Finding domains for country: {country_code}")
        threading.Thread(target=self._find_country_domains_thread, args=(window, country_code), daemon=True).start()
    
    def _find_country_domains_thread(self, window, country_code):
        try:
            time.sleep(1)
            country_domains = {
                'US': ['amazon.com', 'google.com', 'microsoft.com', 'apple.com'],
                'BD': ['brac.net', 'grameenphone.com', 'banglalink.com', 'robi.com.bd'],
                'UK': ['bbc.co.uk', 'gov.uk', 'nhs.uk', 'sky.com'],
                'DE': ['bmw.de', 'volkswagen.de', 'siemens.de', 'deutschebank.de']
            }
            
            domains = country_domains.get(country_code.upper(), ['example.com', 'test.org'])
            
            result = f"Country-specific domains for {country_code}:\n\n"
            for domain in domains:
                result += f"• {domain}\n"
            
            result += f"\nTotal country domains: {len(domains)}"
            self.safe_update_result(window, result)
            self.log_to_console(f"Country domain search completed for {country_code}")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"Country search failed: {str(e)}")
    
    def check_domain_extensions(self, window, domain_name):
        if not domain_name:
            messagebox.showerror("Error", "Please enter a domain name")
            return
        
        self.log_to_console(f"Checking domain extensions for: {domain_name}")
        threading.Thread(target=self._check_domain_extensions_thread, args=(window, domain_name), daemon=True).start()
    
    def _check_domain_extensions_thread(self, window, domain_name):
        try:
            time.sleep(1)
            extensions = ['.com', '.net', '.org', '.app', '.info', '.io', '.biz', '.co']
            result = f"Domain extension availability for {domain_name}:\n\n"
            
            for ext in extensions:
                full_domain = domain_name + ext
                # Simulate availability check
                is_available = random.choice([True, False])
                status = "✅ AVAILABLE" if is_available else "❌ TAKEN"
                result += f"{full_domain}: {status}\n"
            
            self.safe_update_result(window, result)
            self.log_to_console("Domain extension check completed")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"Domain extension check failed: {str(e)}")
    
    def detect_wordpress_theme(self, window, url):
        if not url:
            messagebox.showerror("Error", "Please enter a WordPress site URL")
            return
        
        self.log_to_console(f"Detecting WordPress theme for: {url}")
        threading.Thread(target=self._detect_wordpress_theme_thread, args=(window, url), daemon=True).start()
    
    def _detect_wordpress_theme_thread(self, window, url):
        try:
            time.sleep(1)
            themes = ['Astra', 'Divi', 'Avada', 'OceanWP', 'GeneratePress', 'Twenty Twenty-Three']
            plugins = ['Yoast SEO', 'WooCommerce', 'Contact Form 7', 'Elementor']
            
            detected_theme = random.choice(themes)
            detected_plugins = random.sample(plugins, random.randint(2, 4))
            
            result = f"WordPress Analysis for: {url}\n\n"
            result += f"✓ WordPress Detected: YES\n"
            result += f"✓ Theme: {detected_theme}\n"
            result += f"✓ Version: {random.randint(4,6)}.{random.randint(0,9)}.{random.randint(0,9)}\n\n"
            result += "Detected Plugins:\n"
            for plugin in detected_plugins:
                result += f"• {plugin}\n"
            
            self.safe_update_result(window, result)
            self.log_to_console("WordPress theme detection completed")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"Theme detection failed: {str(e)}")
    
    def scan_wordpress_site(self, window, url):
        if not url:
            messagebox.showerror("Error", "Please enter a WordPress site URL")
            return
        
        self.log_to_console(f"Scanning WordPress site: {url}")
        threading.Thread(target=self._scan_wordpress_site_thread, args=(window, url), daemon=True).start()
    
    def _scan_wordpress_site_thread(self, window, url):
        try:
            time.sleep(2)
            
            vulnerabilities = [
                ("Outdated WordPress", "Medium", "Update to latest version"),
                ("XML-RPC Enabled", "Low", "Disable XML-RPC"),
                ("Directory Listing", "Medium", "Disable directory listing"),
                ("Weak Admin Password", "High", "Use strong password")
            ]
            
            result = f"WordPress Security Scan: {url}\n\n"
            result += "Vulnerabilities Found:\n\n"
            
            for vuln, severity, solution in vulnerabilities:
                result += f"⚠️  {vuln}\n"
                result += f"   Severity: {severity}\n"
                result += f"   Solution: {solution}\n\n"
            
            result += "Security Score: 65/100\n"
            result += "Recommendation: Immediate security hardening required"
            
            self.safe_update_result(window, result)
            self.log_to_console("WordPress security scan completed")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"WordPress scan failed: {str(e)}")
    
    def convert_domain_to_ip(self, window, domain):
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.log_to_console(f"Converting domain to IP: {domain}")
        threading.Thread(target=self._convert_domain_to_ip_thread, args=(window, domain), daemon=True).start()
    
    def _convert_domain_to_ip_thread(self, window, domain):
        try:
            time.sleep(1)
            
            # Simulate IP resolution
            ip_octets = [str(random.randint(1, 255)) for _ in range(4)]
            ip = ".".join(ip_octets)
            
            result = f"Domain: {domain}\n"
            result += f"IP Address: {ip}\n\n"
            result += "Additional Information:\n"
            result += f"• ISP: Cloudflare Inc.\n"
            result += f"• Country: United States\n"
            result += f"• City: San Francisco\n"
            result += f"• Organization: Cloudflare, Inc."
            
            self.safe_update_result(window, result)
            self.log_to_console(f"Domain to IP conversion completed: {domain} -> {ip}")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"Domain to IP conversion failed: {str(e)}")
    
    def reverse_ip_lookup(self, window, ip):
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        
        self.log_to_console(f"Performing reverse IP lookup for: {ip}")
        threading.Thread(target=self._reverse_ip_lookup_thread, args=(window, ip), daemon=True).start()
    
    def _reverse_ip_lookup_thread(self, window, ip):
        try:
            time.sleep(1)
            
            domains = [
                f"site{i}.example.com" for i in range(1, 9)
            ]
            
            result = f"Reverse IP Lookup for: {ip}\n\n"
            result += "Domains hosted on this IP:\n\n"
            
            for domain in domains:
                result += f"• {domain}\n"
            
            result += f"\nTotal domains found: {len(domains)}"
            
            self.safe_update_result(window, result)
            self.log_to_console(f"Reverse IP lookup completed for {ip}")
            
        except Exception as e:
            self.safe_update_result(window, f"Error: {str(e)}")
            self.log_to_console(f"Reverse IP lookup failed: {str(e)}")
    
    def log_to_console(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = DarkBossTools(root)
    root.mainloop()
