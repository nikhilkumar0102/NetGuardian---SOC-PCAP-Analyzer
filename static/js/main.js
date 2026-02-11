/**
 * NetGuardian - Main JavaScript
 */

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

// Enable Bootstrap tooltips/popovers if needed
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    })
});

// Console branding
console.log(`
%c╔═══════════════════════════════════════╗
%c║                                       ║
%c║          NETGUARDIAN SOC              ║
%c║                                       ║
%c║    Enterprise Network Analysis        ║
%c║                                       ║
%c╚═══════════════════════════════════════╝
`, 
'color: #3b82f6; font-weight: bold;',
'color: #3b82f6;',
'color: #3b82f6; font-weight: bold;',
'color: #3b82f6;',
'color: #94a3b8;',
'color: #3b82f6;',
'color: #3b82f6; font-weight: bold;'
);
