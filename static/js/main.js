/**
 * NetGuardian - Main JavaScript
 */

// Animated particles background
document.addEventListener('DOMContentLoaded', function() {
    createParticles();
});

function createParticles() {
    const particlesContainer = document.getElementById('particles');
    if (!particlesContainer) return;
    
    const particleCount = 30;
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 15 + 's';
        particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
        particlesContainer.appendChild(particle);
    }
}

// Smooth scroll
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});

// Auto-dismiss alerts after 5 seconds
setTimeout(() => {
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        const bsAlert = new bootstrap.Alert(alert);
        setTimeout(() => {
            bsAlert.close();
        }, 5000);
    });
}, 100);

// Console easter egg
console.log(`
%c╔═══════════════════════════════════════╗
║                                       ║
║         🛡️  NETGUARDIAN  🛡️          ║
║                                       ║
║    SOC Network Analysis Platform      ║
║         v1.0 - Developed by           ║
║           Nikhil Kumar                ║
║                                       ║
╚═══════════════════════════════════════╝
`, 'color: #00f0ff; font-family: monospace; font-size: 12px;');