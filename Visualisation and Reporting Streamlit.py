import pandas as pd
import numpy as np
import streamlit as st
import json
import re
import email
from urllib.parse import urlparse
import hashlib
import sqlite3
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import warnings
warnings.filterwarnings('ignore')

# ML Libraries
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

class CampaignAwareDetector:
    def __init__(self, db_path='phishing_intelligence.db'):
        self.db_path = db_path
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self.ml_model = None
        self.campaign_data = None
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize database with campaign tables"""
        cursor = self.connection.cursor()
        
        # Create campaigns table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                asn_org TEXT,
                ssl_fingerprint TEXT,
                registrar TEXT,
                num_indicators INTEGER,
                domains TEXT,
                urls TEXT,
                targeted_brands TEXT,
                avg_risk_score REAL,
                dominant_risk_level TEXT,
                source_feeds TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        
        # Create enriched_indicators table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enriched_indicators (
                url TEXT PRIMARY KEY,
                domain TEXT,
                source TEXT,
                first_seen TEXT,
                risk_score REAL,
                risk_level TEXT,
                asn_org TEXT,
                ssl_fingerprint TEXT,
                geoip_country TEXT,
                most_similar_brand TEXT,
                highest_similarity_score REAL,
                campaign_id TEXT
            )
        ''')
        
        self.connection.commit()
    
    def load_and_analyze_campaigns(self, df):
        """Load dataset and analyze campaign patterns"""
        st.info("📊 Analyzing campaign patterns from dataset...")
        
        # Store the dataframe for later use
        self.df = df
        
        # Group by infrastructure patterns to identify campaigns
        campaigns = self.identify_campaigns(df)
        
        # Store campaigns in database
        self.store_campaigns(campaigns)
        
        # Enrich indicators with campaign context
        self.enrich_indicators_with_campaigns(df, campaigns)
        
        return campaigns
    
    def identify_campaigns(self, df):
        """Identify campaigns based on shared infrastructure"""
        campaigns = []
        
        # Strategy 1: Group by ASN + Brand
        asn_campaigns = self._group_by_asn_brand(df)
        campaigns.extend(asn_campaigns)
        
        # Strategy 2: Group by SSL Fingerprint
        ssl_campaigns = self._group_by_ssl_fingerprint(df)
        campaigns.extend(ssl_campaigns)
        
        # Strategy 3: Group by Registrar patterns
        registrar_campaigns = self._group_by_registrar_patterns(df)
        campaigns.extend(registrar_campaigns)
        
        return campaigns
    
    def _group_by_asn_brand(self, df):
        """Group by ASN organization and targeted brands"""
        campaigns = []
        
        # Filter out rows with missing ASN data
        asn_df = df[df['asn_org'].notna() & (df['asn_org'] != 'Unknown')]
        
        grouped = asn_df.groupby(['asn_org', 'most_similar_brand'])
        
        for (asn_org, brand), group in grouped:
            if len(group) >= 2:  # At least 2 indicators for a campaign
                campaign = {
                    'campaign_id': f"CMP-ASN-{hash(f'{asn_org}{brand}') % 1000000}",
                    'asn_org': asn_org,
                    'ssl_fingerprint': 'Multiple',
                    'registrar': 'Unknown',
                    'num_indicators': len(group),
                    'domains': group['domain'].unique().tolist(),
                    'urls': group['url'].head(5).tolist(),  # Limit URLs
                    'targeted_brands': [brand] if brand != 'unknown' else [],
                    'avg_risk_score': round(group['risk_score'].mean(), 2),
                    'dominant_risk_level': group['risk_level'].mode().iloc[0] if len(group['risk_level'].mode()) > 0 else 'MEDIUM',
                    'source_feeds': group['source'].unique().tolist(),
                    'first_seen': group['first_seen'].min(),
                    'last_seen': group['first_seen'].max(),
                    'grouping_strategy': 'ASN_ORGANIZATION'
                }
                campaigns.append(campaign)
        
        return campaigns
    
    def _group_by_ssl_fingerprint(self, df):
        """Group by SSL certificate fingerprints"""
        campaigns = []
        
        # Filter out rows with missing SSL data
        ssl_df = df[df['ssl_fingerprint'].notna() & (df['ssl_fingerprint'] != '')]
        
        grouped = ssl_df.groupby('ssl_fingerprint')
        
        for ssl_fp, group in grouped:
            if len(group) >= 2:
                # Get the most common brand
                brand_counts = group['most_similar_brand'].value_counts()
                primary_brand = brand_counts.index[0] if len(brand_counts) > 0 else 'unknown'
                
                campaign = {
                    'campaign_id': f"CMP-SSL-{hash(ssl_fp) % 1000000}",
                    'asn_org': group['asn_org'].mode().iloc[0] if len(group['asn_org'].mode()) > 0 else 'Unknown',
                    'ssl_fingerprint': ssl_fp,
                    'registrar': 'Unknown',
                    'num_indicators': len(group),
                    'domains': group['domain'].unique().tolist(),
                    'urls': group['url'].head(5).tolist(),
                    'targeted_brands': [primary_brand] if primary_brand != 'unknown' else [],
                    'avg_risk_score': round(group['risk_score'].mean(), 2),
                    'dominant_risk_level': group['risk_level'].mode().iloc[0] if len(group['risk_level'].mode()) > 0 else 'MEDIUM',
                    'source_feeds': group['source'].unique().tolist(),
                    'first_seen': group['first_seen'].min(),
                    'last_seen': group['first_seen'].max(),
                    'grouping_strategy': 'SSL_FINGERPRINT'
                }
                campaigns.append(campaign)
        
        return campaigns
    
    def _group_by_registrar_patterns(self, df):
        """Group by registrar patterns (simulated since we don't have real registrar data)"""
        campaigns = []
        
        # Simulate registrar grouping based on domain patterns
        domain_groups = df.groupby(df['domain'].apply(self._extract_registrar_pattern))
        
        for pattern, group in domain_groups:
            if len(group) >= 3 and pattern != 'unknown':
                campaign = {
                    'campaign_id': f"CMP-REG-{hash(pattern) % 1000000}",
                    'asn_org': 'Multiple',
                    'ssl_fingerprint': 'Multiple',
                    'registrar': pattern,
                    'num_indicators': len(group),
                    'domains': group['domain'].unique().tolist(),
                    'urls': group['url'].head(5).tolist(),
                    'targeted_brands': group['most_similar_brand'].unique().tolist(),
                    'avg_risk_score': round(group['risk_score'].mean(), 2),
                    'dominant_risk_level': group['risk_level'].mode().iloc[0] if len(group['risk_level'].mode()) > 0 else 'MEDIUM',
                    'source_feeds': group['source'].unique().tolist(),
                    'first_seen': group['first_seen'].min(),
                    'last_seen': group['first_seen'].max(),
                    'grouping_strategy': 'REGISTRAR_PATTERN'
                }
                campaigns.append(campaign)
        
        return campaigns
    
    def _extract_registrar_pattern(self, domain):
        """Extract registrar-like patterns from domains"""
        domain_str = str(domain).lower()
        
        if any(pattern in domain_str for pattern in ['namecheap', 'nc']):
            return 'NameCheap'
        elif any(pattern in domain_str for pattern in ['godaddy', 'gd']):
            return 'GoDaddy'
        elif any(pattern in domain_str for pattern in ['cloudflare']):
            return 'Cloudflare'
        elif any(pattern in domain_str for pattern in ['google']):
            return 'Google'
        else:
            return 'unknown'
    
    def store_campaigns(self, campaigns):
        """Store campaigns in database"""
        cursor = self.connection.cursor()
        
        for campaign in campaigns:
            cursor.execute('''
                INSERT OR REPLACE INTO campaigns 
                (campaign_id, asn_org, ssl_fingerprint, registrar, num_indicators, 
                 domains, urls, targeted_brands, avg_risk_score, dominant_risk_level, 
                 source_feeds, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                campaign['campaign_id'],
                campaign['asn_org'],
                campaign['ssl_fingerprint'],
                campaign['registrar'],
                campaign['num_indicators'],
                json.dumps(campaign['domains']),
                json.dumps(campaign['urls']),
                json.dumps(campaign['targeted_brands']),
                campaign['avg_risk_score'],
                campaign['dominant_risk_level'],
                json.dumps(campaign['source_feeds']),
                campaign['first_seen'],
                campaign['last_seen']
            ))
        
        self.connection.commit()
        st.success(f"✅ Stored {len(campaigns)} campaigns in database")
    
    def enrich_indicators_with_campaigns(self, df, campaigns):
        """Enrich individual indicators with campaign context"""
        cursor = self.connection.cursor()
        
        for _, row in df.iterrows():
            # Find matching campaign
            campaign_id = self._find_matching_campaign(row, campaigns)
            
            cursor.execute('''
                INSERT OR REPLACE INTO enriched_indicators 
                (url, domain, source, first_seen, risk_score, risk_level, 
                 asn_org, ssl_fingerprint, geoip_country, most_similar_brand, 
                 highest_similarity_score, campaign_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                row['url'],
                row['domain'],
                row['source'],
                row['first_seen'],
                row.get('risk_score', 0),
                row.get('risk_level', 'UNKNOWN'),
                row.get('asn_org', 'Unknown'),
                row.get('ssl_fingerprint', ''),
                row.get('geoip_country', 'Unknown'),
                row.get('most_similar_brand', 'unknown'),
                row.get('highest_similarity_score', 0),
                campaign_id
            ))
        
        self.connection.commit()
        st.success(f"✅ Enriched {len(df)} indicators with campaign context")
    
    def _find_matching_campaign(self, indicator, campaigns):
        """Find which campaign an indicator belongs to"""
        for campaign in campaigns:
            # Check domain match
            if indicator['domain'] in campaign['domains']:
                return campaign['campaign_id']
            
            # Check ASN match
            if (campaign['asn_org'] != 'Multiple' and 
                campaign['asn_org'] != 'Unknown' and 
                indicator.get('asn_org') == campaign['asn_org']):
                return campaign['campaign_id']
            
            # Check SSL fingerprint match
            if (campaign['ssl_fingerprint'] != 'Multiple' and 
                indicator.get('ssl_fingerprint') == campaign['ssl_fingerprint']):
                return campaign['campaign_id']
        
        return 'UNKNOWN'
    
    def query_campaign_context(self, indicators):
        """Query campaign context for given indicators"""
        campaign_context = {
            'matching_campaigns': [],
            'infrastructure_patterns': {},
            'risk_amplification': 0,
            'campaign_risk_score': 0
        }
        
        cursor = self.connection.cursor()
        
        for domain in indicators.get('domains', []):
            # Query campaigns by domain
            cursor.execute('''
                SELECT c.* FROM campaigns c
                WHERE c.domains LIKE ?
            ''', (f'%{domain}%',))
            
            campaigns = cursor.fetchall()
            for campaign in campaigns:
                campaign_info = {
                    'campaign_id': campaign[0],
                    'asn_org': campaign[1],
                    'ssl_fingerprint': campaign[2],
                    'registrar': campaign[3],
                    'num_indicators': campaign[4],
                    'targeted_brands': json.loads(campaign[7]),
                    'avg_risk_score': campaign[8],
                    'dominant_risk_level': campaign[9],
                    'source_feeds': json.loads(campaign[10])
                }
                campaign_context['matching_campaigns'].append(campaign_info)
        
        # Calculate campaign-based risk amplification - MORE REALISTIC
        if campaign_context['matching_campaigns']:
            campaign_risks = [camp['avg_risk_score'] for camp in campaign_context['matching_campaigns']]
            campaign_context['campaign_risk_score'] = max(campaign_risks)
            
            # More realistic amplification based on campaign strength
            max_campaign_risk = campaign_context['campaign_risk_score']
            num_campaigns = len(campaign_context['matching_campaigns'])
            
            # Gradual amplification formula
            if max_campaign_risk > 80:
                base_amplification = 15  # Strong campaigns get moderate boost
            elif max_campaign_risk > 60:
                base_amplification = 10  # Medium campaigns get smaller boost
            else:
                base_amplification = 5   # Weak campaigns get minimal boost
            
            # Scale by number of campaigns (diminishing returns)
            campaign_multiplier = min(2.0, 1.0 + (num_campaigns * 0.1))
            
            campaign_context['risk_amplification'] = min(25, base_amplification * campaign_multiplier)
        
        return campaign_context
    
    def predict_with_campaign_context(self, indicators):
        """Predict risk with realistic campaign context amplification"""
        # Get campaign context
        campaign_context = self.query_campaign_context(indicators)
        
        # Base risk from individual indicators - MORE GRADUAL
        base_risk = self._calculate_realistic_base_risk(indicators)
        
        # Apply realistic campaign amplification
        campaign_boost = campaign_context['risk_amplification']
        final_risk = min(95, base_risk + campaign_boost)  # Cap at 95% for uncertainty
        
        # Determine phishing probability with confidence levels
        is_phishing, confidence = self._determine_phishing_confidence(final_risk, base_risk, campaign_boost)
        
        return {
            'final_risk_score': final_risk,
            'base_risk_score': base_risk,
            'campaign_amplification': campaign_boost,
            'campaign_context': campaign_context,
            'matching_campaigns_count': len(campaign_context['matching_campaigns']),
            'is_phishing': is_phishing,
            'confidence_level': confidence,
            'risk_category': self._categorize_risk(final_risk)
        }
    
    def _calculate_realistic_base_risk(self, indicators):
        """Calculate realistic base risk from individual indicators"""
        base_risk = 15  # Lower starting point
        
        # URL-based risk - MORE GRADUAL
        url = indicators.get('urls', [''])[0] if indicators.get('urls') else ''
        domain = indicators.get('domains', [''])[0] if indicators.get('domains') else ''
        
        # Domain characteristics - GRADUAL SCORING
        if domain:
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            if any(tld in domain for tld in suspicious_tlds):
                base_risk += 8
            
            # Domain length
            if len(domain) > 30:
                base_risk += 5
            elif len(domain) > 20:
                base_risk += 3
            
            # Hyphen count
            hyphen_count = domain.count('-')
            if hyphen_count >= 3:
                base_risk += 8
            elif hyphen_count >= 2:
                base_risk += 4
        
        # Email header analysis
        sender = indicators.get('sender', '')
        reply_to = indicators.get('reply_to', '')
        
        # Sender-reply-to mismatch
        if sender and reply_to and sender != reply_to:
            domain_sender = self._extract_domain(sender)
            domain_reply = self._extract_domain(reply_to)
            if domain_sender != domain_reply:
                base_risk += 12
        
        # Content analysis - GRADUAL KEYWORD SCORING
        body = indicators.get('body', '').lower()
        subject = indicators.get('subject', '').lower()
        
        # High-risk keywords
        high_risk_keywords = ['urgent', 'verify', 'password', 'security', 'suspended', 'locked']
        high_risk_count = sum(1 for keyword in high_risk_keywords if keyword in body or keyword in subject)
        base_risk += high_risk_count * 3
        
        # Medium-risk keywords
        med_risk_keywords = ['invoice', 'payment', 'billing', 'account', 'login']
        med_risk_count = sum(1 for keyword in med_risk_keywords if keyword in body or keyword in subject)
        base_risk += med_risk_count * 2
        
        # Brand impersonation detection
        if any(brand in body for brand in ['paypal', 'visa', 'mastercard', 'bank']):
            base_risk += 10
        
        return min(base_risk, 65)  # More realistic cap
    
    def _extract_domain(self, email_address):
        """Extract domain from email address"""
        match = re.search(r'@([\w.-]+)', email_address)
        return match.group(1) if match else ''
    
    def _determine_phishing_confidence(self, final_risk, base_risk, campaign_boost):
        """Determine phishing probability with confidence levels"""
        if final_risk >= 70:
            return True, "HIGH"
        elif final_risk >= 55:
            return True, "MEDIUM"
        elif final_risk >= 45:
            return False, "LOW"  # Suspicious but not confident
        else:
            return False, "VERY_LOW"
    
    def _categorize_risk(self, risk_score):
        """Categorize risk with more granular levels"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 65:
            return "HIGH"
        elif risk_score >= 50:
            return "MEDIUM"
        elif risk_score >= 35:
            return "LOW"
        else:
            return "VERY_LOW"

class CampaignEmailProcessor:
    def parse_email(self, email_content):
        """Parse email content and extract indicators"""
        try:
            if isinstance(email_content, str):
                email_message = email.message_from_string(email_content)
            else:
                email_message = email_content
            
            indicators = {
                'sender': email_message.get('From', ''),
                'subject': email_message.get('Subject', ''),
                'reply_to': email_message.get('Reply-To', ''),
                'urls': [],
                'domains': [],
                'body': '',
                'attachments': []
            }
            
            # Extract body
            indicators['body'] = self._extract_email_body(email_message)
            
            # Extract URLs
            indicators['urls'] = self._extract_urls(indicators['body'])
            indicators['domains'] = [urlparse(url).netloc for url in indicators['urls']]
            
            return indicators
            
        except Exception as e:
            st.error(f"Error parsing email: {e}")
            return self._parse_simple_text(email_content)
    
    def _parse_simple_text(self, text):
        """Parse simple text as email content"""
        indicators = {
            'sender': '',
            'subject': '',
            'reply_to': '',
            'urls': self._extract_urls(text),
            'domains': [],
            'body': text,
            'attachments': []
        }
        
        indicators['domains'] = [urlparse(url).netloc for url in indicators['urls']]
        return indicators
    
    def _extract_email_body(self, email_message):
        """Extract text content from email body"""
        body = ""
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body = part.get_payload(decode=True).decode(errors='ignore')
                        break
                    except:
                        pass
        else:
            try:
                body = email_message.get_payload(decode=True).decode(errors='ignore')
            except:
                pass
        return body
    
    def _extract_urls(self, text):
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))

def create_campaign_aware_app():
    """Create the campaign-aware Streamlit application"""
    st.set_page_config(
        page_title="Campaign-Aware Phishing Detection",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.markdown("""
    <style>
    .main-header { font-size: 2.5rem; color: #1f77b4; text-align: center; margin-bottom: 2rem; }
    .campaign-card { background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 10px; border-left: 5px solid #007bff; }
    .risk-critical { color: #8b0000; font-weight: bold; background-color: #ffcccc; padding: 2px 8px; border-radius: 4px; }
    .risk-high { color: #dc3545; font-weight: bold; background-color: red ; padding: 2px 8px; border-radius: 4px; }
    .risk-medium { color: #fd7e14; font-weight: bold; background-color: #fff3cd; padding: 2px 8px; border-radius: 4px; }
    .risk-low { color: #20c997; font-weight: bold; background-color: #d1ecf1; padding: 2px 8px; border-radius: 4px; }
    .risk-very-low { color: #6c757d; font-weight: bold; background-color: #f8f9fa; padding: 2px 8px; border-radius: 4px; }
    .confidence-high { color: #dc3545; }
    .confidence-medium { color: #fd7e14; }
    .confidence-low { color: #ffc107; }
    .confidence-very-low { color: #20c997; }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<div class="main-header">🛡️ Campaign-Aware Phishing Detection</div>', unsafe_allow_html=True)
    
    # Initialize session state
    if 'detector' not in st.session_state:
        st.session_state.detector = CampaignAwareDetector()
    if 'processor' not in st.session_state:
        st.session_state.processor = CampaignEmailProcessor()
    if 'campaigns_loaded' not in st.session_state:
        st.session_state.campaigns_loaded = False
    if 'campaigns_data' not in st.session_state:
        st.session_state.campaigns_data = None
    
    # Sidebar
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.selectbox(
        "Choose Mode",
        ["📊 Campaign Dashboard", "🔍 Analyze Email", "🏗️ Infrastructure Analysis", "📈 Campaign Analytics"]
    )
    
    if app_mode == "📊 Campaign Dashboard":
        show_campaign_dashboard()
    elif app_mode == "🔍 Analyze Email":
        analyze_email_with_campaigns()
    elif app_mode == "🏗️ Infrastructure Analysis":
        show_infrastructure_analysis()
    elif app_mode == "📈 Campaign Analytics":
        show_campaign_analytics()

def show_campaign_dashboard():
    """Display campaign overview dashboard"""
    st.header("📊 Campaign Intelligence Dashboard")
    
    # Load dataset and analyze campaigns
    if not st.session_state.campaigns_loaded:
        if st.button("🚀 Load Dataset & Analyze Campaigns"):
            with st.spinner("Loading dataset and analyzing campaign patterns..."):
                try:
                    df = pd.read_csv('phishing_data_comprehensive_enhanced.csv')
                    st.success(f"✅ Loaded {len(df)} indicators")
                    
                    # Analyze campaigns
                    campaigns = st.session_state.detector.load_and_analyze_campaigns(df)
                    st.session_state.campaigns_data = campaigns
                    st.session_state.campaigns_loaded = True
                    
                    st.success(f"🎯 Identified {len(campaigns)} campaigns")
                    
                except FileNotFoundError:
                    st.error("❌ Dataset file not found. Please ensure 'phishing_data_comprehensive_enhanced.csv' is available.")
                    return
    
    if st.session_state.campaigns_loaded:
        campaigns = st.session_state.campaigns_data
        
        # Campaign summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Campaigns", len(campaigns))
        
        with col2:
            high_risk_campaigns = len([c for c in campaigns if c['avg_risk_score'] > 70])
            st.metric("High-Risk Campaigns", high_risk_campaigns)
        
        with col3:
            total_indicators = sum(c['num_indicators'] for c in campaigns)
            st.metric("Total Indicators", total_indicators)
        
        with col4:
            avg_campaign_size = total_indicators / len(campaigns) if campaigns else 0
            st.metric("Avg Campaign Size", f"{avg_campaign_size:.1f}")
        
        # Campaign list
        st.subheader("🎯 Identified Campaigns")
        
        for campaign in sorted(campaigns, key=lambda x: x['avg_risk_score'], reverse=True)[:10]:
            risk_class = f"risk-{campaign['dominant_risk_level'].lower().replace(' ', '-')}"
            with st.container():
                st.markdown(f"""
                <div class="campaign-card">
                    <h4>🔍 {campaign['campaign_id']} | {campaign['grouping_strategy']}</h4>
                    <p><strong>Targets:</strong> {', '.join(campaign['targeted_brands']) if campaign['targeted_brands'] else 'Various'}</p>
                    <p><strong>Infrastructure:</strong> ASN: {campaign['asn_org']} | SSL: {campaign['ssl_fingerprint'][:20]}...</p>
                    <p><strong>Risk:</strong> <span class="{risk_class}">{campaign['avg_risk_score']}</span> | 
                       <strong>Indicators:</strong> {campaign['num_indicators']}</p>
                    <p><strong>Domains:</strong> {', '.join(campaign['domains'][:3])}{'...' if len(campaign['domains']) > 3 else ''}</p>
                </div>
                """, unsafe_allow_html=True)

def analyze_email_with_campaigns():
    """Analyze email with campaign context"""
    st.header("🔍 Analyze Email with Campaign Intelligence")
    
    email_content = st.text_area(
        "Paste email content:",
        height=200,
        placeholder="Paste email content here..."
    )
    
    if st.button("Analyze with Campaign Context") and email_content:
        with st.spinner("Analyzing email with campaign intelligence..."):
            processor = st.session_state.processor
            detector = st.session_state.detector
            
            # Parse email
            indicators = processor.parse_email(email_content)
            
            if indicators:
                # Display basic info
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📧 Email Information")
                    st.write(f"**Subject:** {indicators['subject']}")
                    st.write(f"**Sender:** {indicators['sender']}")
                    st.write(f"**Reply-To:** {indicators['reply_to']}")
                    st.write(f"**URLs Found:** {len(indicators['urls'])}")
                    st.write(f"**Domains Found:** {len(indicators['domains'])}")
                
                with col2:
                    if indicators['urls']:
                        st.subheader("🌐 Detected URLs")
                        for url in indicators['urls']:
                            st.code(url)
                    
                    if indicators['domains']:
                        st.subheader("🏷️ Detected Domains")
                        for domain in indicators['domains']:
                            st.write(f"`{domain}`")
                
                # Campaign-aware analysis
                st.subheader("🤖 Campaign-Aware Analysis")
                result = detector.predict_with_campaign_context(indicators)
                
                # Display results with better visualization
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    risk_class = f"risk-{result['risk_category'].lower().replace(' ', '-')}"
                    st.markdown(f"<h3 style='text-align: center;'>Final Risk Score</h3>", unsafe_allow_html=True)
                    st.markdown(f"<h1 style='text-align: center;' class='{risk_class}'>{result['final_risk_score']:.1f}</h1>", unsafe_allow_html=True)
                    st.markdown(f"<p style='text-align: center;'><strong>Category:</strong> {result['risk_category']}</p>", unsafe_allow_html=True)
                
                with col2:
                    st.metric("Base Risk", f"{result['base_risk_score']:.1f}")
                    st.metric("Campaign Boost", f"+{result['campaign_amplification']:.1f}")
                
                with col3:
                    confidence_class = f"confidence-{result['confidence_level'].lower().replace('_', '-')}"
                    st.markdown(f"<h3 style='text-align: center;'>Confidence</h3>", unsafe_allow_html=True)
                    st.markdown(f"<h2 style='text-align: center;' class='{confidence_class}'>{result['confidence_level'].replace('_', ' ').title()}</h2>", unsafe_allow_html=True)
                
                with col4:
                    if result['is_phishing']:
                        if result['confidence_level'] == "HIGH":
                            st.error("🚨 LIKELY PHISHING")
                        else:
                            st.warning("⚠️ SUSPICIOUS")
                    else:
                        if result['confidence_level'] == "VERY_LOW":
                            st.success("🛡️ LIKELY LEGITIMATE")
                        else:
                            st.info("🔍 NEEDS REVIEW")
                
                # Risk breakdown
                st.subheader("📊 Risk Breakdown")
                
                risk_data = {
                    'Component': ['Base Email Analysis', 'Campaign Context', 'Final Score'],
                    'Risk Score': [result['base_risk_score'], result['campaign_amplification'], result['final_risk_score']],
                    'Type': ['Base', 'Amplification', 'Final']
                }
                
                fig = px.bar(risk_data, x='Component', y='Risk Score', color='Type',
                            title='Risk Score Components',
                            color_discrete_map={'Base': '#ff6b6b', 'Amplification': '#fd7e14', 'Final': '#dc3545'})
                st.plotly_chart(fig)
                
                # Campaign context
                if result['campaign_context']['matching_campaigns']:
                    st.subheader("🎯 Matching Campaigns")
                    
                    for campaign in result['campaign_context']['matching_campaigns'][:5]:  # Limit to top 5
                        risk_class = f"risk-{campaign['dominant_risk_level'].lower()}"
                        st.write(f"""
                        **{campaign['campaign_id']}**
                        - **Targets:** {', '.join(campaign['targeted_brands'])}
                        - **Infrastructure:** {campaign['asn_org']} | SSL: {campaign['ssl_fingerprint'][:20]}...
                        - **Campaign Risk:** <span class="{risk_class}">{campaign['avg_risk_score']} ({campaign['dominant_risk_level']})</span>
                        - **Indicators:** {campaign['num_indicators']}
                        - **Sources:** {', '.join(campaign['source_feeds'][:2])}
                        """, unsafe_allow_html=True)
                else:
                    st.info("ℹ️ No known campaign matches found")

def show_infrastructure_analysis():
    """Show infrastructure pattern analysis"""
    st.header("🏗️ Infrastructure Pattern Analysis")
    
    if not st.session_state.campaigns_loaded:
        st.warning("Please load the dataset first from the Campaign Dashboard")
        return
    
    campaigns = st.session_state.campaigns_data
    
    # ASN Analysis
    st.subheader("🌐 ASN Organization Patterns")
    asn_data = {}
    for campaign in campaigns:
        asn = campaign['asn_org']
        if asn not in ['Multiple', 'Unknown']:
            if asn not in asn_data:
                asn_data[asn] = []
            asn_data[asn].append(campaign)
    
    # Top ASNs by campaign count
    top_asns = sorted(asn_data.items(), key=lambda x: len(x[1]), reverse=True)[:10]
    
    for asn, asn_campaigns in top_asns:
        with st.expander(f"🔧 {asn} ({len(asn_campaigns)} campaigns)"):
            for campaign in asn_campaigns:
                st.write(f"- {campaign['campaign_id']}: {campaign['targeted_brands']} | Risk: {campaign['avg_risk_score']}")
    
    # SSL Fingerprint Analysis
    st.subheader("🔐 SSL Certificate Patterns")
    ssl_data = {}
    for campaign in campaigns:
        ssl = campaign['ssl_fingerprint']
        if ssl not in ['Multiple', '']:
            if ssl not in ssl_data:
                ssl_data[ssl] = []
            ssl_data[ssl].append(campaign)
    
    # Top SSL fingerprints
    top_ssl = sorted(ssl_data.items(), key=lambda x: len(x[1]), reverse=True)[:5]
    
    for ssl, ssl_campaigns in top_ssl:
        with st.expander(f"📄 {ssl[:30]}... ({len(ssl_campaigns)} campaigns)"):
            for campaign in ssl_campaigns:
                st.write(f"- {campaign['campaign_id']}: {campaign['targeted_brands']}")

def show_campaign_analytics():
    """Show campaign analytics and insights"""
    st.header("📈 Campaign Analytics")
    
    if not st.session_state.campaigns_loaded:
        st.warning("Please load the dataset first from the Campaign Dashboard")
        return
    
    campaigns = st.session_state.campaigns_data
    df = pd.DataFrame(campaigns)
    
    # Risk distribution
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.histogram(df, x='avg_risk_score', nbins=20,
                          title='Campaign Risk Score Distribution',
                          color_discrete_sequence=["#3d1111"])
        st.plotly_chart(fig)
    
    with col2:
        risk_level_counts = df['dominant_risk_level'].value_counts()
        fig = px.pie(values=risk_level_counts.values,
                    names=risk_level_counts.index,
                    title='Campaign Risk Level Distribution')
        st.plotly_chart(fig)
    
    # Campaign size vs risk
    fig = px.scatter(df, x='num_indicators', y='avg_risk_score',
                    size='num_indicators', color='dominant_risk_level',
                    hover_data=['campaign_id'],
                    title='Campaign Size vs Risk Score')
    st.plotly_chart(fig)
    
    # Targeted brands analysis
    st.subheader("🎯 Targeted Brands Analysis")
    all_brands = []
    for brands in df['targeted_brands']:
        all_brands.extend(brands)
    
    brand_counts = pd.Series(all_brands).value_counts()
    top_brands = brand_counts.head(10)
    
    fig = px.bar(x=top_brands.values, y=top_brands.index,
                orientation='h',
                title='Top 10 Targeted Brands',
                labels={'x': 'Number of Campaigns', 'y': 'Brand'})
    st.plotly_chart(fig)

if __name__ == "__main__":
    create_campaign_aware_app()