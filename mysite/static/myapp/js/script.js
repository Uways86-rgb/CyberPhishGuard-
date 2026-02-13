// CyberSecurity Theme JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initParticles();
    initLoadingScreen();
    initThemeSwitcher();
    initStatsCounter();
    initSmoothScrolling();
    initNavbarEffects();
});

// Particle System
function initParticles() {
    const particlesContainer = document.getElementById('particles-container');
    if (!particlesContainer) return;

    const particleCount = 50;

    for (let i = 0; i < particleCount; i++) {
        createParticle(particlesContainer);
    }

    function createParticle(container) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.cssText = `
            position: absolute;
            width: ${Math.random() * 4 + 1}px;
            height: ${Math.random() * 4 + 1}px;
            background: ${Math.random() > 0.5 ? '#00ff88' : '#00ccff'};
            border-radius: 50%;
            left: ${Math.random() * 100}%;
            top: ${Math.random() * 100}%;
            opacity: ${Math.random() * 0.5 + 0.1};
            animation: float ${Math.random() * 10 + 10}s linear infinite;
        `;

        container.appendChild(particle);

        // Remove particle after animation
        setTimeout(() => {
            particle.remove();
            createParticle(container);
        }, Math.random() * 10000 + 10000);
    }
}



// Loading Screen
function initLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    if (!loadingScreen) {
        console.warn('Loading screen element not found');
        return;
    }

    console.log('Loading screen found, hiding immediately for testing');
    // Hide loading screen immediately for testing
    loadingScreen.style.opacity = '0';
    setTimeout(() => {
        loadingScreen.style.display = 'none';
        console.log('Loading screen hidden');
    }, 500);
}

// Theme Switcher
function initThemeSwitcher() {
    const themeBtn = document.getElementById('theme-toggle');
    const themeOptions = document.querySelector('.theme-options');
    if (!themeBtn || !themeOptions) return;

    let isOpen = false;

    themeBtn.addEventListener('click', () => {
        isOpen = !isOpen;
        themeOptions.style.display = isOpen ? 'block' : 'none';
    });

    // Close theme options when clicking outside
    document.addEventListener('click', (e) => {
        if (!themeBtn.contains(e.target) && !themeOptions.contains(e.target)) {
            isOpen = false;
            themeOptions.style.display = 'none';
        }
    });

    // Theme option handlers
    document.querySelectorAll('.theme-option').forEach(option => {
        option.addEventListener('click', () => {
            const theme = option.getAttribute('data-theme');
            applyTheme(theme);
            isOpen = false;
            themeOptions.style.display = 'none';
        });
    });
}

function applyTheme(theme) {
    const body = document.body;
    body.className = theme;

    // Store theme preference
    localStorage.setItem('cyberTheme', theme);
}

// Load saved theme
const savedTheme = localStorage.getItem('cyberTheme');
if (savedTheme) {
    applyTheme(savedTheme);
}

// Stats Counter Animation
function initStatsCounter() {
    const statNumbers = document.querySelectorAll('[data-target]');

    statNumbers.forEach(stat => {
        const target = parseInt(stat.getAttribute('data-target'));
        const duration = 2000; // 2 seconds
        const increment = target / (duration / 16); // 60fps
        let current = 0;

        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                stat.textContent = target.toLocaleString();
                clearInterval(timer);
            } else {
                stat.textContent = Math.floor(current).toLocaleString();
            }
        }, 16);
    });
}

// Smooth Scrolling
function initSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Navbar Effects
function initNavbarEffects() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    let lastScrollTop = 0;

    window.addEventListener('scroll', () => {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;

        // Add background blur on scroll
        if (scrollTop > 50) {
            navbar.style.background = 'rgba(26, 26, 46, 0.98)';
        } else {
            navbar.style.background = 'rgba(26, 26, 46, 0.95)';
        }

        // Hide/show navbar on scroll
        if (scrollTop > lastScrollTop && scrollTop > 100) {
            navbar.style.transform = 'translateY(-100%)';
        } else {
            navbar.style.transform = 'translateY(0)';
        }

        lastScrollTop = scrollTop;
    });
}

// Utility Functions
function animateOnScroll() {
    const elements = document.querySelectorAll('.fade-in');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    });

    elements.forEach(element => {
        observer.observe(element);
    });
}

// Initialize scroll animations
animateOnScroll();

// Add loading states to buttons (excluding submit buttons)
document.addEventListener('click', function(e) {
    if ((e.target.classList.contains('btn-glow') || e.target.classList.contains('btn-primary')) && e.target.type !== 'submit') {
        const btn = e.target;
        const originalText = btn.textContent;

        btn.disabled = true;
        btn.textContent = 'Processing...';

        // Reset after 2 seconds (for demo purposes)
        setTimeout(() => {
            btn.disabled = false;
            btn.textContent = originalText;
        }, 2000);
    }
});

// Cyber typing effect for hero title
function initTypingEffect() {
    const heroTitle = document.querySelector('.hero-title');
    if (!heroTitle) return;

    const text = heroTitle.textContent;
    heroTitle.textContent = '';
    heroTitle.style.borderRight = '2px solid #00ff88';

    let i = 0;
    const timer = setInterval(() => {
        if (i < text.length) {
            heroTitle.textContent += text.charAt(i);
            i++;
        } else {
            clearInterval(timer);
            setTimeout(() => {
                heroTitle.style.borderRight = 'none';
            }, 500);
        }
    }, 100);
}

// Initialize typing effect
initTypingEffect();

// Real-time clock for dashboard
function updateClock() {
    const clockElements = document.querySelectorAll('#current-time, #last-scan-time');
    const now = new Date();

    clockElements.forEach(element => {
        if (element.id === 'current-time') {
            element.textContent = now.toLocaleString();
        } else if (element.id === 'last-scan-time') {
            // Update last scan time randomly for demo
            if (Math.random() < 0.01) { // 1% chance every second
                element.textContent = now.toLocaleString();
            }
        }
    });
}

// Update clock every second
setInterval(updateClock, 1000);

// Add glow effects on hover for cards
document.querySelectorAll('.stat-card, .feature-card, .dashboard-card, .scan-card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.boxShadow = '0 0 30px rgba(0, 255, 136, 0.3)';
    });

    card.addEventListener('mouseleave', function() {
        this.style.boxShadow = '';
    });
});

// Initialize tooltips for better UX
function initTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');

    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', function(e) {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = this.getAttribute('data-tooltip');
            tooltip.style.cssText = `
                position: absolute;
                background: rgba(0, 0, 0, 0.8);
                color: #00ff88;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 12px;
                z-index: 1000;
                pointer-events: none;
                top: ${e.pageY - 30}px;
                left: ${e.pageX + 10}px;
            `;

            document.body.appendChild(tooltip);

            this.addEventListener('mouseleave', () => {
                tooltip.remove();
            });

            this.addEventListener('mousemove', (e) => {
                tooltip.style.top = `${e.pageY - 30}px`;
                tooltip.style.left = `${e.pageX + 10}px`;
            });
        });
    });
}

// Initialize tooltips
initTooltips();

// Add keyboard navigation support
document.addEventListener('keydown', function(e) {
    // Close modals with Escape key
    if (e.key === 'Escape') {
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(modal => {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) bsModal.hide();
        });
    }

    // Theme switcher with 'T' key
    if (e.key === 't' || e.key === 'T') {
        const themeBtn = document.getElementById('theme-toggle');
        if (themeBtn) themeBtn.click();
    }
});

// Performance optimization: Lazy load images
function lazyLoadImages() {
    const images = document.querySelectorAll('img[data-src]');

    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.classList.remove('lazy');
                observer.unobserve(img);
            }
        });
    });

    images.forEach(img => imageObserver.observe(img));
}

// Initialize lazy loading
lazyLoadImages();

// Add accessibility improvements
function initAccessibility() {
    // Add ARIA labels where needed
    document.querySelectorAll('button:not([aria-label])').forEach(btn => {
        if (btn.textContent.trim()) {
            btn.setAttribute('aria-label', btn.textContent.trim());
        }
    });

    // Improve focus indicators
    document.querySelectorAll('a, button, input, select, textarea').forEach(element => {
        element.addEventListener('focus', function() {
            this.style.outline = '2px solid #00ff88';
        });

        element.addEventListener('blur', function() {
            this.style.outline = '';
        });
    });
}

// Initialize accessibility features
initAccessibility();

// Error handling for failed resource loads
window.addEventListener('error', function(e) {
    console.warn('Resource failed to load:', e.target.src || e.target.href);
    // Could implement fallback loading here
});

// Service worker registration for PWA capabilities (if needed)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        // navigator.serviceWorker.register('/sw.js');
    });
}
