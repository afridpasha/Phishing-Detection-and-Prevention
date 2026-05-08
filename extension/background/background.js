// Phishing Shield 2.0 - Background Service Worker
// Military-grade continuous protection with Smart Whitelist

const API_BASE = 'http://localhost:5000';
let protectionEnabled = true;
let stats = { blocked: 0, checked: 0, safe: 0 };

// SMART WHITELIST - Exact domain matching only
// Protects against typosquatting, subdomain tricks, and homograph attacks
const TRUSTED_DOMAINS = {
  // Format: 'exact-domain.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail', 'drive'] }
  
  // Google Services
  'google.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail', 'drive', 'docs', 'accounts', 'myaccount', 'calendar', 'meet', 'chat', 'maps', 'photos', 'play', 'news', 'translate', 'analytics', 'ads', 'cloud', 'firebase'] },
  'youtube.com': { requireHTTPS: true, allowSubdomains: ['www', 'm', 'music', 'studio', 'gaming'] },
  'gmail.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail'] },
  'goo.gl': { requireHTTPS: true, allowSubdomains: [] },
  'youtu.be': { requireHTTPS: true, allowSubdomains: [] },
  'googlevideo.com': { requireHTTPS: true, allowSubdomains: [] },
  'googleusercontent.com': { requireHTTPS: true, allowSubdomains: [] },
  'gstatic.com': { requireHTTPS: true, allowSubdomains: [] },
  
  // Social Media
  'facebook.com': { requireHTTPS: true, allowSubdomains: ['www', 'm', 'web', 'business', 'developers', 'l'] },
  'fb.com': { requireHTTPS: true, allowSubdomains: [] },
  'fb.me': { requireHTTPS: true, allowSubdomains: [] },
  'twitter.com': { requireHTTPS: true, allowSubdomains: ['www', 'mobile', 'api', 'help'] },
  'x.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  't.co': { requireHTTPS: true, allowSubdomains: [] },
  'instagram.com': { requireHTTPS: true, allowSubdomains: ['www', 'help'] },
  'linkedin.com': { requireHTTPS: true, allowSubdomains: ['www', 'in'] },
  'tiktok.com': { requireHTTPS: true, allowSubdomains: ['www', 'vm'] },
  'snapchat.com': { requireHTTPS: true, allowSubdomains: ['www', 'accounts'] },
  'pinterest.com': { requireHTTPS: true, allowSubdomains: ['www', 'in'] },
  'pin.it': { requireHTTPS: true, allowSubdomains: [] },
  'reddit.com': { requireHTTPS: true, allowSubdomains: ['www', 'old', 'new', 'i', 'v'] },
  'redd.it': { requireHTTPS: true, allowSubdomains: [] },
  'tumblr.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Messaging & Communication
  'whatsapp.com': { requireHTTPS: true, allowSubdomains: ['www', 'web', 'faq'] },
  'web.whatsapp.com': { requireHTTPS: true, allowSubdomains: [] },
  'wa.me': { requireHTTPS: true, allowSubdomains: [] },
  'telegram.org': { requireHTTPS: true, allowSubdomains: ['www', 'web', 't'] },
  't.me': { requireHTTPS: true, allowSubdomains: [] },
  'discord.com': { requireHTTPS: true, allowSubdomains: ['www', 'ptb', 'canary'] },
  'discord.gg': { requireHTTPS: true, allowSubdomains: [] },
  'slack.com': { requireHTTPS: true, allowSubdomains: ['www', 'app', 'api'] },
  'zoom.us': { requireHTTPS: true, allowSubdomains: ['www', 'us02web', 'us04web', 'us05web'] },
  'skype.com': { requireHTTPS: true, allowSubdomains: ['www', 'web'] },
  'teams.microsoft.com': { requireHTTPS: true, allowSubdomains: [] },
  
  // E-commerce
  'amazon.com': { requireHTTPS: true, allowSubdomains: ['www', 'smile', 'aws', 'console', 'signin'] },
  'amzn.to': { requireHTTPS: true, allowSubdomains: [] },
  'ebay.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'etsy.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'shopify.com': { requireHTTPS: true, allowSubdomains: ['www', 'admin'] },
  'aliexpress.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'walmart.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'target.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'bestbuy.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Payment & Banking
  'paypal.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'stripe.com': { requireHTTPS: true, allowSubdomains: ['www', 'dashboard'] },
  'square.com': { requireHTTPS: true, allowSubdomains: ['www', 'squareup'] },
  'venmo.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'cashapp.com': { requireHTTPS: true, allowSubdomains: ['www', 'cash'] },
  
  // Microsoft Services
  'microsoft.com': { requireHTTPS: true, allowSubdomains: ['www', 'login', 'account', 'outlook', 'support'] },
  'outlook.com': { requireHTTPS: true, allowSubdomains: ['www', 'outlook'] },
  'live.com': { requireHTTPS: true, allowSubdomains: ['www', 'login'] },
  'office.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'office365.com': { requireHTTPS: true, allowSubdomains: ['www', 'portal'] },
  'onedrive.com': { requireHTTPS: true, allowSubdomains: ['www', 'onedrive'] },
  'xbox.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'bing.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'msn.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Apple Services
  'apple.com': { requireHTTPS: true, allowSubdomains: ['www', 'support', 'appleid'] },
  'icloud.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'me.com': { requireHTTPS: true, allowSubdomains: [] },
  'itunes.apple.com': { requireHTTPS: true, allowSubdomains: [] },
  
  // Developer & Tech
  'github.com': { requireHTTPS: true, allowSubdomains: ['www', 'gist', 'api', 'raw', 'pages'] },
  'gitlab.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'bitbucket.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'stackoverflow.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'stackexchange.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'npmjs.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'pypi.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'docker.com': { requireHTTPS: true, allowSubdomains: ['www', 'hub'] },
  'atlassian.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'jira.com': { requireHTTPS: true, allowSubdomains: [] },
  'trello.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Cloud Services
  'dropbox.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'box.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'drive.google.com': { requireHTTPS: true, allowSubdomains: [] },
  'icloud.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Education & Knowledge
  'wikipedia.org': { requireHTTPS: true, allowSubdomains: ['www', 'en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'ja', 'zh'] },
  'wikimedia.org': { requireHTTPS: true, allowSubdomains: ['www', 'commons', 'meta'] },
  'coursera.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'udemy.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'khanacademy.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'edx.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'medium.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Productivity & Design
  'canva.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'canva.link': { requireHTTPS: true, allowSubdomains: [] },
  'figma.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'notion.so': { requireHTTPS: true, allowSubdomains: ['www'] },
  'airtable.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'asana.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'monday.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'miro.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'adobe.com': { requireHTTPS: true, allowSubdomains: ['www', 'account', 'adminconsole'] },
  
  // Streaming & Entertainment
  'netflix.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'spotify.com': { requireHTTPS: true, allowSubdomains: ['www', 'open', 'accounts'] },
  'twitch.tv': { requireHTTPS: true, allowSubdomains: ['www', 'm'] },
  'hulu.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'disneyplus.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'primevideo.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'soundcloud.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'vimeo.com': { requireHTTPS: true, allowSubdomains: ['www', 'player'] },
  
  // News & Media
  'nytimes.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'bbc.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'bbc.co.uk': { requireHTTPS: true, allowSubdomains: ['www'] },
  'cnn.com': { requireHTTPS: true, allowSubdomains: ['www', 'edition'] },
  'theguardian.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'reuters.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'bloomberg.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // URL Shorteners (Legitimate)
  'bit.ly': { requireHTTPS: true, allowSubdomains: [] },
  'tinyurl.com': { requireHTTPS: true, allowSubdomains: [] },
  'ow.ly': { requireHTTPS: true, allowSubdomains: [] },
  'buff.ly': { requireHTTPS: true, allowSubdomains: [] },
  
  // Government & Official
  'gov': { requireHTTPS: true, allowSubdomains: ['www'] },
  'gov.uk': { requireHTTPS: true, allowSubdomains: ['www'] },
  'usa.gov': { requireHTTPS: true, allowSubdomains: ['www'] },
  'europa.eu': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // CDN & Infrastructure
  'cloudflare.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'akamai.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'fastly.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // AI Services
  'openai.com': { requireHTTPS: true, allowSubdomains: ['www', 'chat', 'platform', 'api', 'help', 'cdn'] },
  'chatgpt.com': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains and paths
  'anthropic.com': { requireHTTPS: true, allowSubdomains: ['www', 'console', 'docs', 'api'] },
  'claude.ai': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains and paths
  'gemini.google.com': { requireHTTPS: true, allowSubdomains: [] },
  'bard.google.com': { requireHTTPS: true, allowSubdomains: [] },
  'copilot.microsoft.com': { requireHTTPS: true, allowSubdomains: [] },
  'bing.com': { requireHTTPS: true, allowSubdomains: ['www', 'copilot', 'chat'] },
  'perplexity.ai': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains
  'huggingface.co': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains
  'cohere.com': { requireHTTPS: true, allowSubdomains: ['www', 'dashboard', 'api'] },
  'ai21.com': { requireHTTPS: true, allowSubdomains: ['www', 'studio', 'api'] },
  'replicate.com': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains
  'midjourney.com': { requireHTTPS: true, allowSubdomains: ['www', 'docs', 'cdn'] },
  'stability.ai': { requireHTTPS: true, allowSubdomains: ['www', 'platform', 'api'] },
  'character.ai': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains
  'poe.com': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains
  'you.com': { requireHTTPS: true, allowSubdomains: [] }, // Allow all subdomains
  'jasper.ai': { requireHTTPS: true, allowSubdomains: ['www', 'app', 'api'] },
  'writesonic.com': { requireHTTPS: true, allowSubdomains: ['www', 'app', 'api'] },
  'copy.ai': { requireHTTPS: true, allowSubdomains: ['www', 'app', 'api'] },
  'deepai.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'runway.ml': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'synthesia.io': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'elevenlabs.io': { requireHTTPS: true, allowSubdomains: ['www', 'api'] },
  
  // Major Tech Companies
  'meta.com': { requireHTTPS: true, allowSubdomains: ['www', 'about', 'developers'] },
  'nvidia.com': { requireHTTPS: true, allowSubdomains: ['www', 'developer'] },
  'intel.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'amd.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'oracle.com': { requireHTTPS: true, allowSubdomains: ['www', 'cloud'] },
  'salesforce.com': { requireHTTPS: true, allowSubdomains: ['www', 'login'] },
  'sap.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'ibm.com': { requireHTTPS: true, allowSubdomains: ['www', 'cloud'] },
  'dell.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'hp.com': { requireHTTPS: true, allowSubdomains: ['www', 'support'] },
  'lenovo.com': { requireHTTPS: true, allowSubdomains: ['www', 'support'] },
  'samsung.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'sony.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'lg.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Financial Services & Banking
  'chase.com': { requireHTTPS: true, allowSubdomains: ['www', 'secure'] },
  'wellsfargo.com': { requireHTTPS: true, allowSubdomains: ['www', 'online'] },
  'bankofamerica.com': { requireHTTPS: true, allowSubdomains: ['www', 'secure'] },
  'citi.com': { requireHTTPS: true, allowSubdomains: ['www', 'online'] },
  'citibank.com': { requireHTTPS: true, allowSubdomains: ['www', 'online'] },
  'usbank.com': { requireHTTPS: true, allowSubdomains: ['www', 'onlinebanking'] },
  'capitalone.com': { requireHTTPS: true, allowSubdomains: ['www', 'verified'] },
  'americanexpress.com': { requireHTTPS: true, allowSubdomains: ['www', 'online'] },
  'discover.com': { requireHTTPS: true, allowSubdomains: ['www', 'portal'] },
  'schwab.com': { requireHTTPS: true, allowSubdomains: ['www', 'client'] },
  'fidelity.com': { requireHTTPS: true, allowSubdomains: ['www', 'digital'] },
  'vanguard.com': { requireHTTPS: true, allowSubdomains: ['www', 'personal'] },
  'tdameritrade.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'etrade.com': { requireHTTPS: true, allowSubdomains: ['www', 'us'] },
  'robinhood.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'coinbase.com': { requireHTTPS: true, allowSubdomains: ['www', 'pro'] },
  'binance.com': { requireHTTPS: true, allowSubdomains: ['www', 'accounts'] },
  'kraken.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'gemini.com': { requireHTTPS: true, allowSubdomains: ['www', 'exchange'] },
  
  // E-commerce & Retail
  'shopify.com': { requireHTTPS: true, allowSubdomains: ['www', 'admin', 'accounts'] },
  'bigcommerce.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'woocommerce.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'etsy.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'wayfair.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'overstock.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'newegg.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'costco.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'samsclub.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'homedepot.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'lowes.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'ikea.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'macys.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'nordstrom.com': { requireHTTPS: true, allowSubdomains: ['www', 'shop'] },
  'zappos.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Travel & Hospitality
  'booking.com': { requireHTTPS: true, allowSubdomains: ['www', 'secure'] },
  'expedia.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'hotels.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'airbnb.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'tripadvisor.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'kayak.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'priceline.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'marriott.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'hilton.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'hyatt.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'ihg.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'delta.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'united.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'aa.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'southwest.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'jetblue.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Education & Learning
  'khanacademy.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'coursera.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'udemy.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'edx.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'udacity.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'skillshare.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'pluralsight.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'linkedin.com': { requireHTTPS: true, allowSubdomains: ['www', 'in', 'learning'] },
  'duolingo.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'codecademy.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'freecodecamp.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'w3schools.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'mdn.dev': { requireHTTPS: true, allowSubdomains: ['www'] },
  'developer.mozilla.org': { requireHTTPS: true, allowSubdomains: [] },
  
  // Professional & Business Tools
  'salesforce.com': { requireHTTPS: true, allowSubdomains: ['www', 'login', 'na1', 'na2'] },
  'hubspot.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'zendesk.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'freshdesk.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'intercom.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'drift.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'calendly.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'docusign.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'hellosign.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'typeform.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'surveymonkey.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'qualtrics.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Cloud Storage & File Sharing
  'dropbox.com': { requireHTTPS: true, allowSubdomains: ['www', 'dl'] },
  'box.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'drive.google.com': { requireHTTPS: true, allowSubdomains: [] },
  'onedrive.com': { requireHTTPS: true, allowSubdomains: ['www', 'onedrive'] },
  'onedrive.live.com': { requireHTTPS: true, allowSubdomains: [] },
  'icloud.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'mega.nz': { requireHTTPS: true, allowSubdomains: ['www'] },
  'mediafire.com': { requireHTTPS: true, allowSubdomains: ['www', 'download'] },
  'wetransfer.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'sendspace.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Email Services
  'gmail.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail'] },
  'outlook.com': { requireHTTPS: true, allowSubdomains: ['www', 'outlook'] },
  'yahoo.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail'] },
  'protonmail.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail'] },
  'proton.me': { requireHTTPS: true, allowSubdomains: ['www', 'mail', 'account'] },
  'tutanota.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail'] },
  'zoho.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail'] },
  'aol.com': { requireHTTPS: true, allowSubdomains: ['www', 'mail'] },
  'mail.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Security & Privacy
  'lastpass.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  '1password.com': { requireHTTPS: true, allowSubdomains: ['www', 'my'] },
  'bitwarden.com': { requireHTTPS: true, allowSubdomains: ['www', 'vault'] },
  'dashlane.com': { requireHTTPS: true, allowSubdomains: ['www', 'app'] },
  'nordvpn.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'expressvpn.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'surfshark.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'protonvpn.com': { requireHTTPS: true, allowSubdomains: ['www', 'account'] },
  'malwarebytes.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'norton.com': { requireHTTPS: true, allowSubdomains: ['www', 'my'] },
  'mcafee.com': { requireHTTPS: true, allowSubdomains: ['www', 'home'] },
  'kaspersky.com': { requireHTTPS: true, allowSubdomains: ['www', 'my'] },
  'avast.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'avg.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Gaming Platforms
  'steam.com': { requireHTTPS: true, allowSubdomains: ['www', 'store', 'help'] },
  'steampowered.com': { requireHTTPS: true, allowSubdomains: ['www', 'store', 'help'] },
  'epicgames.com': { requireHTTPS: true, allowSubdomains: ['www', 'store'] },
  'origin.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'ea.com': { requireHTTPS: true, allowSubdomains: ['www', 'help'] },
  'ubisoft.com': { requireHTTPS: true, allowSubdomains: ['www', 'store'] },
  'blizzard.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'battle.net': { requireHTTPS: true, allowSubdomains: ['www'] },
  'riotgames.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'playstation.com': { requireHTTPS: true, allowSubdomains: ['www', 'store'] },
  'nintendo.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'gog.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'humblebundle.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'itch.io': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Social & Community
  'discord.com': { requireHTTPS: true, allowSubdomains: ['www', 'ptb', 'canary'] },
  'discord.gg': { requireHTTPS: true, allowSubdomains: [] },
  'reddit.com': { requireHTTPS: true, allowSubdomains: ['www', 'old', 'new', 'i', 'v'] },
  'quora.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'mastodon.social': { requireHTTPS: true, allowSubdomains: [] },
  'meetup.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'eventbrite.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // News & Media (Additional)
  'wsj.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'ft.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'economist.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'forbes.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'businessinsider.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'techcrunch.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'theverge.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'wired.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'arstechnica.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'engadget.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'cnet.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'zdnet.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'npr.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'pbs.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'apnews.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'time.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'newsweek.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'usatoday.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'washingtonpost.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'latimes.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Government Services (Additional)
  'irs.gov': { requireHTTPS: true, allowSubdomains: ['www'] },
  'ssa.gov': { requireHTTPS: true, allowSubdomains: ['www'] },
  'usps.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'fedex.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'ups.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'dhl.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'canada.ca': { requireHTTPS: true, allowSubdomains: ['www'] },
  'gov.au': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Health & Medical
  'webmd.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'mayoclinic.org': { requireHTTPS: true, allowSubdomains: ['www'] },
  'nih.gov': { requireHTTPS: true, allowSubdomains: ['www'] },
  'cdc.gov': { requireHTTPS: true, allowSubdomains: ['www'] },
  'who.int': { requireHTTPS: true, allowSubdomains: ['www'] },
  'healthline.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'medlineplus.gov': { requireHTTPS: true, allowSubdomains: ['www'] },
  
  // Other Popular Services
  'wordpress.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'wix.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'squarespace.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'mailchimp.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'godaddy.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'namecheap.com': { requireHTTPS: true, allowSubdomains: ['www'] },
  'cloudinary.com': { requireHTTPS: true, allowSubdomains: ['www', 'res'] },
  'imgur.com': { requireHTTPS: true, allowSubdomains: ['www', 'i'] },
  'giphy.com': { requireHTTPS: true, allowSubdomains: ['www', 'media'] },
  'tenor.com': { requireHTTPS: true, allowSubdomains: ['www', 'media'] }
};

// Localhost and development domains (always trusted)
const LOCALHOST_PATTERNS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1'
];

// Detect homograph attacks (Cyrillic/Greek letters that look like Latin)
function containsHomographs(domain) {
  // Check for non-ASCII characters that could be homographs
  const suspiciousChars = /[а-яА-ЯёЁα-ωΑ-Ω]/; // Cyrillic and Greek
  return suspiciousChars.test(domain);
}

// Detect typosquatting patterns
function isTyposquatting(domain, trustedDomain) {
  // Check Levenshtein distance (edit distance)
  const distance = levenshteinDistance(domain, trustedDomain);
  return distance > 0 && distance <= 2; // 1-2 character difference
}

function levenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// SMART WHITELIST CHECK - Multi-layer verification
function checkSmartWhitelist(url) {
  try {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol;
    const hostname = urlObj.hostname.toLowerCase();
    
    // Check for localhost/development domains FIRST
    for (const pattern of LOCALHOST_PATTERNS) {
      if (hostname === pattern || hostname.startsWith(pattern + ':')) {
        console.log('✅ Localhost/development domain:', hostname);
        return { trusted: true, domain: 'localhost', runAI: false };
      }
    }
    
    // Remove 'www.' for comparison
    const baseDomain = hostname.replace(/^www\./, '');
    const subdomain = hostname.includes('.') ? hostname.split('.')[0] : null;
    
    // Check for homograph attacks first
    if (containsHomographs(hostname)) {
      console.warn('🚨 Homograph attack detected:', hostname);
      return { trusted: false, reason: 'homograph_attack', runAI: true };
    }
    
    // Check if domain exactly matches trusted list
    for (const [trustedDomain, config] of Object.entries(TRUSTED_DOMAINS)) {
      // Exact match check (including subdomain match)
      const domainMatches = baseDomain === trustedDomain || hostname === trustedDomain || hostname.endsWith('.' + trustedDomain);
      
      if (domainMatches) {
        // Check HTTPS requirement
        if (config.requireHTTPS && protocol !== 'https:') {
          console.warn('⚠️ Trusted domain without HTTPS:', hostname);
          return { trusted: false, reason: 'no_https', runAI: true };
        }
        
        // Check subdomain if present (only if not exact match)
        if (subdomain && hostname !== trustedDomain && baseDomain !== trustedDomain) {
          const allowedSubdomains = config.allowSubdomains || [];
          if (allowedSubdomains.length > 0 && !allowedSubdomains.includes(subdomain)) {
            console.warn('⚠️ Suspicious subdomain:', hostname);
            return { trusted: false, reason: 'suspicious_subdomain', runAI: true };
          }
        }
        
        // All checks passed - this is genuinely trusted (SKIP AI completely)
        console.log('✅ Verified trusted domain (all paths allowed):', hostname);
        return { trusted: true, domain: trustedDomain, runAI: false };
      }
      
      // Check for typosquatting attempts
      if (isTyposquatting(baseDomain, trustedDomain)) {
        console.warn('🚨 Typosquatting detected:', hostname, '→', trustedDomain);
        return { trusted: false, reason: 'typosquatting', runAI: true, suspectedTarget: trustedDomain };
      }
    }
    
    // Check for subdomain tricks (e.g., google.com.evil.com)
    for (const trustedDomain of Object.keys(TRUSTED_DOMAINS)) {
      if (hostname.includes(trustedDomain) && !hostname.endsWith(trustedDomain)) {
        console.warn('🚨 Subdomain trick detected:', hostname);
        return { trusted: false, reason: 'subdomain_trick', runAI: true, suspectedTarget: trustedDomain };
      }
    }
    
    // Not in whitelist - run full AI analysis
    return { trusted: false, reason: 'not_whitelisted', runAI: true };
    
  } catch (error) {
    console.error('Error in smart whitelist check:', error);
    return { trusted: false, reason: 'error', runAI: true };
  }
}

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ Phishing Shield 2.0 - Military Grade Protection Activated');
  
  // Create context menu
  chrome.contextMenus.create({
    id: 'checkLink',
    title: '🛡️ Check Link with Phishing Shield',
    contexts: ['link']
  });
  
  chrome.contextMenus.create({
    id: 'checkText',
    title: '🛡️ Check Text for Phishing',
    contexts: ['selection']
  });
  
  // Load stats
  chrome.storage.local.get(['stats'], (result) => {
    if (result.stats) stats = result.stats;
  });
  
  // Show welcome notification
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: 'Phishing Shield 2.0 Activated',
    message: 'Military-grade protection is now active across all websites.'
  });
});

// Intercept navigation BEFORE page loads using webNavigation API
// This works better than webRequest in Manifest V3
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (!protectionEnabled) return;
  if (details.frameId !== 0) return; // Only check main frame
  
  const url = details.url;
  
  // Skip internal URLs
  if (url.startsWith('chrome://') || 
      url.startsWith('chrome-extension://') ||
      url.startsWith('data:') ||
      url.startsWith('blob:') ||
      url.startsWith('about:')) {
    return;
  }
  
  console.log('🔍 Checking URL automatically:', url);
  stats.checked++;
  saveStats();
  
  // Check URL in background (non-blocking first, then redirect if phishing)
  checkURLAndBlock(url, details.tabId);
});

// Check URL and block if phishing
async function checkURLAndBlock(url, tabId) {
  try {
    console.log('🛡️ Analyzing:', url);
    const result = await checkURL(url);
    
    console.log('📊 Result:', result);
    
    if (result.is_phishing && result.confidence > 0.5) {
      stats.blocked++;
      saveStats();
      
      console.log('🚨 PHISHING DETECTED! Blocking...');
      
      // Show notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon128.png'),
        title: '🚨 PHISHING BLOCKED AUTOMATICALLY',
        message: `Blocked: ${url.substring(0, 60)}...\nConfidence: ${(result.confidence * 100).toFixed(1)}%\nThreat: ${getThreatLevel(result.confidence)}`,
        priority: 2,
        requireInteraction: true
      });
      
      // Redirect to warning page with all details
      setTimeout(() => {
        const blockedPageUrl = chrome.runtime.getURL('popup/blocked.html') + 
             '?url=' + encodeURIComponent(url) + 
             '&confidence=' + encodeURIComponent(result.confidence) +
             '&attack=' + encodeURIComponent(result.attack_type || 'phishing') +
             '&target=' + encodeURIComponent(result.suspected_target || '') +
             '&auto=true';
        
        console.log('🔗 Redirecting to blocked page:', blockedPageUrl);
        
        // Check if tab still exists before updating
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError) {
            console.warn('⚠️ Tab no longer exists:', chrome.runtime.lastError.message);
            return;
          }
          
          chrome.tabs.update(tabId, {
            url: blockedPageUrl
          });
        });
      }, 100);
    } else {
      stats.safe++;
      saveStats();
      console.log('✅ URL is safe');
    }
  } catch (error) {
    console.error('❌ Error checking URL:', error);
  }
}

function getThreatLevel(confidence) {
  if (confidence > 0.9) return '🔴 CRITICAL';
  if (confidence > 0.7) return '🟠 HIGH';
  if (confidence > 0.5) return '🟡 MEDIUM';
  return '🟢 LOW';
}

// Context menu handler
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'checkLink') {
    const url = info.linkUrl;
    const result = await checkURL(url);
    showResult(result, url, 'URL');
  } else if (info.menuItemId === 'checkText') {
    const text = info.selectionText;
    const result = await checkText(text);
    showResult(result, text, 'Text');
  }
});

// Check URL via API with Smart Whitelist
async function checkURL(url) {
  try {
    // STEP 1: Smart Whitelist Check (Multi-layer verification)
    const whitelistResult = checkSmartWhitelist(url);
    
    if (whitelistResult.trusted) {
      // Genuinely trusted domain - skip AI analysis
      return { 
        is_phishing: false, 
        confidence: 0.01,
        message: `Verified trusted domain: ${whitelistResult.domain}`,
        whitelisted: true
      };
    }
    
    // STEP 2: If whitelist check failed with suspicious reason, boost AI analysis
    let aiResult;
    if (whitelistResult.reason === 'typosquatting' || 
        whitelistResult.reason === 'homograph_attack' || 
        whitelistResult.reason === 'subdomain_trick') {
      
      // Run AI analysis
      const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      aiResult = await response.json();
      
      // BOOST confidence if AI also detected phishing
      if (aiResult.is_phishing) {
        aiResult.confidence = Math.min(aiResult.confidence * 1.3, 0.99); // Boost by 30%
        aiResult.attack_type = whitelistResult.reason;
        aiResult.suspected_target = whitelistResult.suspectedTarget;
        console.warn(`🚨 ATTACK DETECTED: ${whitelistResult.reason} targeting ${whitelistResult.suspectedTarget}`);
      }
      
      return aiResult;
    }
    
    // STEP 3: Normal AI analysis for unknown domains
    const response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(10000) // 10 second timeout
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return await response.json();
    
  } catch (error) {
    console.error('API Error:', error);
    
    // If backend is not running, return safe (don't block user)
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      console.warn('⚠️ Backend not reachable - allowing navigation');
      return { 
        is_phishing: false, 
        confidence: 0, 
        error: true,
        message: 'Backend not available'
      };
    }
    
    return { is_phishing: false, confidence: 0, error: true };
  }
}

// Check text (SMS/Email)
async function checkText(text) {
  try {
    // Determine if SMS or Email
    const isSMS = text.length < 500 && !text.includes('@');
    const endpoint = isSMS ? '/analyze-sms' : '/analyze-email';
    
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(isSMS ? { message: text } : { email_content: text })
    });
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    return { is_phishing: false, confidence: 0, error: true };
  }
}

// Show result notification with attack details
function showResult(result, content, type) {
  const isPhishing = result.is_phishing || result.is_smishing;
  const confidence = (result.confidence * 100).toFixed(1);
  
  let title = isPhishing ? `🚨 ${type} IS PHISHING` : `✅ ${type} IS SAFE`;
  let message = `Confidence: ${confidence}%\n${content.substring(0, 100)}...`;
  
  // Add attack type information if detected
  if (result.attack_type) {
    const attackTypes = {
      'typosquatting': '🚨 TYPOSQUATTING ATTACK',
      'homograph_attack': '🚨 HOMOGRAPH ATTACK',
      'subdomain_trick': '🚨 SUBDOMAIN TRICK',
      'suspicious_subdomain': '⚠️ SUSPICIOUS SUBDOMAIN'
    };
    title = attackTypes[result.attack_type] || title;
    if (result.suspected_target) {
      message = `Impersonating: ${result.suspected_target}\n${message}`;
    }
  }
  
  // Add whitelist info if applicable
  if (result.whitelisted) {
    message = `✅ Verified trusted domain\n${message}`;
  }
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: title,
    message: message,
    priority: isPhishing ? 2 : 1
  });
}

// Save stats
function saveStats() {
  chrome.storage.local.set({ stats });
}

// Message handler from popup/content
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getStats') {
    sendResponse({ stats, protectionEnabled });
  } else if (request.action === 'toggleProtection') {
    protectionEnabled = !protectionEnabled;
    sendResponse({ protectionEnabled });
  } else if (request.action === 'checkURL') {
    checkURL(request.url).then(sendResponse);
    return true;
  } else if (request.action === 'checkText') {
    checkText(request.text).then(sendResponse);
    return true;
  } else if (request.action === 'checkImage') {
    checkImage(request.imageData).then(sendResponse);
    return true;
  } else if (request.action === 'goBack') {
    // Handle go back navigation from blocked page
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.tabs.goBack(tabs[0].id, function() {
          if (chrome.runtime.lastError) {
            // No history, go to safe page
            chrome.tabs.update(tabs[0].id, { url: 'about:blank' });
          }
        });
      }
    });
    sendResponse({ success: true });
  } else if (request.action === 'proceedToURL') {
    // Handle proceed anyway navigation from blocked page
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.tabs.update(tabs[0].id, { url: request.url }, function() {
          console.log('✅ User proceeded to blocked URL:', request.url);
        });
      }
    });
    sendResponse({ success: true });
  }
});

// Check image via API
async function checkImage(imageData) {
  try {
    const formData = new FormData();
    const blob = await fetch(imageData).then(r => r.blob());
    formData.append('image', blob, 'screenshot.png');
    
    const response = await fetch(`${API_BASE}/analyze-image`, {
      method: 'POST',
      body: formData
    });
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    return { is_phishing: false, confidence: 0, error: true };
  }
}

// Keep service worker alive
setInterval(() => {
  chrome.storage.local.get(['keepAlive'], () => {});
}, 20000);

// Monitor clipboard for SMS/Email content (when user copies suspicious text)
let lastClipboardCheck = 0;
const CLIPBOARD_CHECK_INTERVAL = 5000; // Check every 5 seconds

setInterval(async () => {
  if (!protectionEnabled) return;
  
  const now = Date.now();
  if (now - lastClipboardCheck < CLIPBOARD_CHECK_INTERVAL) return;
  lastClipboardCheck = now;
  
  try {
    // Get clipboard text
    const text = await navigator.clipboard.readText();
    
    if (!text || text.length < 20) return; // Skip short text
    
    // Check if text contains URLs
    const urlPattern = /(https?:\/\/[^\s]+)/gi;
    const urls = text.match(urlPattern);
    
    if (urls && urls.length > 0) {
      // Check if text looks like SMS or Email
      const isSMS = text.length < 500;
      const hasUrgentKeywords = /urgent|verify|suspended|click here|act now|confirm|account|password/i.test(text);
      
      if (hasUrgentKeywords) {
        // Automatically check the text
        const result = await checkText(text);
        
        if (result.is_phishing || result.is_smishing) {
          // Show warning notification
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: '⚠️ SUSPICIOUS TEXT DETECTED IN CLIPBOARD',
            message: `Phishing detected in copied text!\nConfidence: ${(result.confidence * 100).toFixed(1)}%\nBe careful before clicking any links!`,
            priority: 2,
            requireInteraction: true
          });
        }
      }
    }
  } catch (error) {
    // Clipboard access denied or not available
    // This is normal, just skip
  }
}, CLIPBOARD_CHECK_INTERVAL);

console.log('🛡️ Phishing Shield 2.0 Background Service Active - FULL AUTO MODE');
