# RFC 9460 Compliance Analysis Project Plan

## Project Overview

An open-source research project to analyze RFC 9460 (SVCB/HTTPS DNS Records) adoption across the top 100 websites globally, with results published via GitHub Pages.

## Project Goals

1. **Data Collection**: Systematically query and log HTTPS/SVCB DNS records for top websites
2. **Analysis**: Identify trends in HTTP/3 adoption, ECH deployment, and DNS-based service discovery
3. **Visualization**: Create interactive dashboards showing RFC 9460 compliance metrics
4. **Documentation**: Provide comprehensive analysis and insights for the community
5. **Automation**: Set up periodic scans to track adoption over time

## Repository Structure

```
rfc9460-check/
├── src/                        # Source code
│   ├── checker.py             # Main DNS checking script
│   ├── analyzer.py            # Data analysis utilities
│   └── visualizer.py          # Visualization generation
├── data/                      # Raw and processed data
│   ├── websites/              # Website lists
│   ├── raw/                   # Raw scan results (CSV)
│   └── processed/             # Analyzed data (JSON)
├── docs/                      # GitHub Pages site
│   ├── index.html             # Main dashboard
│   ├── analysis.md            # Detailed analysis
│   ├── methodology.md         # Research methodology
│   ├── assets/                # CSS, JS, images
│   └── data/                  # JSON data for visualizations
├── notebooks/                 # Jupyter notebooks for analysis
│   ├── exploratory.ipynb      # Initial data exploration
│   └── trends.ipynb           # Trend analysis
├── tests/                     # Unit tests
├── .github/                   # GitHub-specific files
│   ├── workflows/             # GitHub Actions
│   │   ├── scan.yml           # Periodic scanning
│   │   └── deploy.yml         # Deploy to GitHub Pages
│   └── ISSUE_TEMPLATE/        # Issue templates
├── LICENSE                    # MIT License
├── README.md                  # Project documentation
├── requirements.txt           # Python dependencies
└── PROJECT_PLAN.md           # This file

```

## Development Phases

### Phase 1: Foundation (Current)
- [x] Create basic RFC 9460 checker script
- [x] Implement CSV logging functionality
- [x] Build initial website list (top 100)
- [x] Write project documentation
- [ ] Initialize git repository with proper structure
- [ ] Set up Python package structure
- [ ] Add comprehensive error handling and logging

### Phase 2: Data Collection & Analysis
- [ ] Enhance checker with additional RFC 9460 parameters
- [ ] Create data analysis scripts
- [ ] Build Jupyter notebooks for exploration
- [ ] Generate initial dataset and baseline metrics
- [ ] Implement data validation and quality checks
- [ ] Create historical tracking capability

### Phase 3: Visualization & Reporting
- [ ] Design GitHub Pages site structure
- [ ] Create interactive dashboards using D3.js/Chart.js
- [ ] Build compliance scorecards for each domain
- [ ] Generate trend charts over time
- [ ] Create exportable reports (PDF/HTML)
- [ ] Implement search and filtering capabilities

### Phase 4: Automation & CI/CD
- [ ] Set up GitHub Actions for periodic scans (daily/weekly)
- [ ] Automate data processing and analysis
- [ ] Auto-generate and deploy visualizations
- [ ] Create alerts for significant changes
- [ ] Implement data archival strategy
- [ ] Set up issue creation for scan failures

### Phase 5: Community & Enhancement
- [ ] Add support for custom domain lists
- [ ] Create API endpoints for data access
- [ ] Implement contributor guidelines
- [ ] Add internationalization support
- [ ] Create educational content about RFC 9460
- [ ] Build comparison tools with other DNS standards

## Technical Components

### Data Collection
- **Primary Tool**: Python with dnspython library
- **DNS Servers**: Multiple resolvers for redundancy (Google, Cloudflare, OpenDNS)
- **Rate Limiting**: Throttled queries to respect DNS infrastructure
- **Error Recovery**: Retry logic with exponential backoff

### Data Schema
```json
{
  "metadata": {
    "version": "1.0.0",
    "scan_date": "ISO 8601 timestamp",
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "total_domains": 100
  },
  "results": [
    {
      "domain": "example.com",
      "variants": ["root", "www"],
      "https_record": {
        "present": true,
        "priority": 1,
        "target": "example.com",
        "parameters": {
          "alpn": ["h3", "h2"],
          "port": null,
          "ipv4hint": ["192.0.2.1"],
          "ipv6hint": ["2001:db8::1"],
          "ech": true
        }
      },
      "compliance_score": 85,
      "features": {
        "http3": true,
        "ech": true,
        "custom_port": false,
        "ip_hints": true
      }
    }
  ],
  "statistics": {
    "total_compliant": 45,
    "http3_adoption": 38,
    "ech_deployment": 12,
    "average_score": 42.5
  }
}
```

### Analysis Metrics

#### Primary Metrics
- **Adoption Rate**: Percentage of domains with HTTPS records
- **HTTP/3 Support**: Domains advertising "h3" ALPN
- **ECH Deployment**: Domains with ECH configuration
- **IP Hint Usage**: Domains providing IPv4/IPv6 hints

#### Secondary Metrics
- **Priority Distribution**: Analysis of priority values
- **Target Patterns**: Aliasing vs service mode usage
- **Port Diversity**: Non-standard port configurations
- **ALPN Combinations**: Common protocol offerings

#### Trend Metrics
- **Adoption Growth**: Month-over-month changes
- **Feature Velocity**: Speed of new feature adoption
- **Regional Differences**: Geographic analysis if applicable
- **Industry Sectors**: Adoption by website category

## GitHub Pages Site

### Landing Page (index.html)
- Executive summary dashboard
- Key statistics cards
- Adoption timeline chart
- Top performers leaderboard
- Quick search functionality

### Analysis Page
- Detailed findings and insights
- Statistical breakdowns
- Correlation analysis
- Industry comparisons
- Technical deep-dives

### Methodology Page
- Research approach
- Data collection process
- Limitations and caveats
- Reproducibility instructions
- Citation guidelines

### Interactive Features
- Domain lookup tool
- Compliance checker
- Trend explorer
- Data export options
- API documentation

## Automation Strategy

### GitHub Actions Workflows

#### Daily Scan (`scan.yml`)
```yaml
- Runs at 00:00 UTC daily
- Executes RFC 9460 checker
- Commits results to data/raw/
- Triggers analysis pipeline
```

#### Analysis Pipeline (`analyze.yml`)
```yaml
- Triggered by new scan data
- Processes raw CSV files
- Generates statistics
- Updates visualizations
- Commits to data/processed/
```

#### Deploy (`deploy.yml`)
```yaml
- Triggered by changes to docs/
- Builds static site
- Deploys to GitHub Pages
- Sends notifications
```

## Success Metrics

1. **Coverage**: Successfully scan 95%+ of target domains
2. **Accuracy**: <1% false positive/negative rate
3. **Performance**: Complete scan in <10 minutes
4. **Availability**: 99.9% uptime for GitHub Pages site
5. **Community**: 100+ stars, 10+ contributors within 6 months
6. **Impact**: Referenced in at least 3 academic/industry papers

## Timeline

- **Week 1-2**: Complete Phase 1 & 2
- **Week 3-4**: Implement Phase 3
- **Week 5-6**: Deploy Phase 4
- **Month 2+**: Iterate on Phase 5

## Open Source Considerations

### License
MIT License for maximum compatibility and adoption

### Contributing Guidelines
- Pull request templates
- Code of conduct
- Development setup instructions
- Testing requirements
- Documentation standards

### Community Building
- Discord/Slack channel
- Regular blog posts
- Conference presentations
- Academic partnerships
- Industry collaboration

## Risk Mitigation

### Technical Risks
- **DNS Query Failures**: Multiple resolver fallbacks
- **Rate Limiting**: Distributed scanning, caching
- **Data Quality**: Validation, cross-verification
- **Scalability**: Efficient data structures, pagination

### Project Risks
- **Maintainer Burnout**: Clear governance, automation
- **Scope Creep**: Defined milestones, issue triage
- **Data Privacy**: No PII collection, transparent methods
- **Sustainability**: Low maintenance design, documentation

## Next Steps

1. Initialize git repository with `.gitignore`
2. Create GitHub repository with appropriate settings
3. Set up GitHub Pages branch structure
4. Implement enhanced error handling in checker
5. Create first analysis notebook
6. Design initial visualizations
7. Write comprehensive test suite
8. Set up GitHub Actions workflows

## Contact

- GitHub Issues: Primary communication channel
- Email: [To be added]
- Twitter: [To be added]

---

*This plan is a living document and will be updated as the project evolves.*
