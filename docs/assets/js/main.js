// Main JavaScript for RFC 9460 Adoption Tracker

// Domain details data
const domainDetails = {
    'discord.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: ['h3', 'h2'],
        http3: true,
        ipv4hint: ['162.159.128.233', '162.159.129.233'],
        ipv6hint: ['2606:4700:7::a29f:80e9', '2606:4700:7::a29f:81e9'],
        ech: false,
        score: 85,
        analysis: 'Discord demonstrates strong RFC 9460 implementation with HTTP/3 support and comprehensive IP hints.'
    },
    'cloudflare.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: ['h3', 'h2'],
        http3: true,
        ipv4hint: ['104.16.132.229', '104.16.133.229'],
        ipv6hint: ['2606:4700::6810:84e5', '2606:4700::6810:85e5'],
        ech: false,
        score: 85,
        analysis: 'Cloudflare, as a CDN provider, leads in RFC 9460 adoption with full HTTP/3 and dual-stack IP hints.'
    },
    'doordash.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: ['h3', 'h2'],
        http3: true,
        ipv4hint: ['151.101.1.118', '151.101.65.118'],
        ipv6hint: [],
        ech: false,
        score: 85,
        analysis: 'DoorDash has implemented HTTPS records with HTTP/3 support and IPv4 hints for improved performance.'
    },
    'google.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: ['h3', 'h2'],
        http3: true,
        ipv4hint: [],
        ipv6hint: [],
        ech: false,
        score: 70,
        analysis: 'Google has basic HTTPS record implementation with HTTP/3 support but lacks IP address hints.'
    },
    'facebook.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: ['h3', 'h2'],
        http3: true,
        ipv4hint: [],
        ipv6hint: [],
        ech: false,
        score: 70,
        analysis: 'Facebook implements HTTPS records with HTTP/3 but without additional optimization features.'
    },
    'instagram.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: ['h3', 'h2'],
        http3: true,
        ipv4hint: [],
        ipv6hint: [],
        ech: false,
        score: 70,
        analysis: 'Instagram (Meta) has adopted HTTPS records with HTTP/3 protocol support.'
    },
    'stackoverflow.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: ['h2'],
        http3: false,
        ipv4hint: ['151.101.1.69', '151.101.65.69'],
        ipv6hint: ['2a03:2880:f10e:83:face:b00c:0:25de'],
        ech: false,
        score: 65,
        analysis: 'Stack Overflow has HTTPS records with IP hints but lacks HTTP/3 support.'
    },
    'linkedin.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: [],
        http3: false,
        ipv4hint: [],
        ipv6hint: [],
        ech: false,
        score: 42.5,
        analysis: 'LinkedIn has basic HTTPS record presence but minimal feature implementation.'
    },
    'youtube.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: [],
        http3: false,
        ipv4hint: [],
        ipv6hint: [],
        ech: false,
        score: 40,
        analysis: 'YouTube has implemented HTTPS records but without advanced features.'
    },
    'theverge.com': {
        https_record: true,
        priority: 1,
        target: '.',
        alpn: [],
        http3: false,
        ipv4hint: [],
        ipv6hint: [],
        ech: false,
        score: 32.5,
        analysis: 'The Verge has minimal HTTPS record implementation without optimization features.'
    }
};

// Show domain details in modal
function showDetails(domain) {
    const details = domainDetails[domain];
    if (!details) {
        console.error('No details found for domain:', domain);
        return;
    }

    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    modalTitle.textContent = `${domain} - RFC 9460 Compliance Details`;

    let detailsHTML = `
        <div class="row">
            <div class="col-md-6">
                <h5>DNS Record Information</h5>
                <table class="table table-sm">
                    <tr>
                        <td><strong>HTTPS Record:</strong></td>
                        <td>${details.https_record ? '<span class="badge bg-success">Present</span>' : '<span class="badge bg-danger">Absent</span>'}</td>
                    </tr>
                    <tr>
                        <td><strong>Priority:</strong></td>
                        <td>${details.priority}</td>
                    </tr>
                    <tr>
                        <td><strong>Target:</strong></td>
                        <td><code>${details.target}</code></td>
                    </tr>
                    <tr>
                        <td><strong>Compliance Score:</strong></td>
                        <td>
                            <div class="progress" style="height: 20px;">
                                <div class="progress-bar bg-${details.score >= 80 ? 'success' : details.score >= 60 ? 'warning' : 'info'}"
                                     style="width: ${details.score}%">${details.score}/100</div>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
            <div class="col-md-6">
                <h5>Protocol Support</h5>
                <table class="table table-sm">
                    <tr>
                        <td><strong>ALPN Protocols:</strong></td>
                        <td>${details.alpn.length > 0 ? details.alpn.map(p => `<span class="badge bg-info">${p}</span>`).join(' ') : '<span class="text-muted">None</span>'}</td>
                    </tr>
                    <tr>
                        <td><strong>HTTP/3 Support:</strong></td>
                        <td>${details.http3 ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-secondary">No</span>'}</td>
                    </tr>
                    <tr>
                        <td><strong>ECH Config:</strong></td>
                        <td>${details.ech ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-secondary">No</span>'}</td>
                    </tr>
                </table>
            </div>
        </div>

        <div class="row mt-3">
            <div class="col-12">
                <h5>IP Address Hints</h5>
                <div class="row">
                    <div class="col-md-6">
                        <strong>IPv4 Hints:</strong>
                        ${details.ipv4hint.length > 0 ?
                            '<ul class="list-unstyled">' + details.ipv4hint.map(ip => `<li><code>${ip}</code></li>`).join('') + '</ul>' :
                            '<p class="text-muted">None provided</p>'}
                    </div>
                    <div class="col-md-6">
                        <strong>IPv6 Hints:</strong>
                        ${details.ipv6hint.length > 0 ?
                            '<ul class="list-unstyled">' + details.ipv6hint.map(ip => `<li><code>${ip}</code></li>`).join('') + '</ul>' :
                            '<p class="text-muted">None provided</p>'}
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-3">
            <div class="col-12">
                <h5>Analysis</h5>
                <p>${details.analysis}</p>
            </div>
        </div>

        <div class="row mt-3">
            <div class="col-12">
                <h5>DNS Query Example</h5>
                <pre class="bg-dark text-light p-3 rounded"><code>$ dig +short ${domain} TYPE65</code></pre>
            </div>
        </div>
    `;

    modalBody.innerHTML = detailsHTML;

    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('detailModal'));
    modal.show();
}

// Smooth scrolling for navigation links
document.addEventListener('DOMContentLoaded', function() {
    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const offset = 80; // Account for fixed navbar
                const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - offset;
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Add animation on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
            }
        });
    }, observerOptions);

    // Observe all cards and feature items
    document.querySelectorAll('.card, .feature-item, .stat-card').forEach(el => {
        observer.observe(el);
    });

    // Update active nav link on scroll
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.navbar-nav a[href^="#"]');

    window.addEventListener('scroll', () => {
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            const sectionHeight = section.clientHeight;
            if (window.pageYOffset >= sectionTop && window.pageYOffset < sectionTop + sectionHeight) {
                current = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href').slice(1) === current) {
                link.classList.add('active');
            }
        });
    });
});

// Copy to clipboard functionality
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success message
        const toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white bg-success border-0';
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    Copied to clipboard!
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        document.body.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        setTimeout(() => toast.remove(), 3000);
    });
}

// Add click handlers to code blocks
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('pre code').forEach(block => {
        block.style.cursor = 'pointer';
        block.title = 'Click to copy';
        block.addEventListener('click', function() {
            copyToClipboard(this.textContent);
        });
    });
});
