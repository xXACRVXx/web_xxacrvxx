// Mejoras adicionales para la página de status
document.addEventListener('DOMContentLoaded', function() {
    
    // Añadir indicador de conectividad
    function addConnectivityIndicator() {
        const banner = document.querySelector('.page-banner .container .row .col-lg-8');
        if (banner) {
            const indicator = document.createElement('div');
            indicator.className = 'connectivity-status mt-2';
            indicator.innerHTML = `
                <small class="status-text-muted">
                    <span id="connectivity-dot" class="status-indicator online"></span>
                    <span id="connectivity-text">Conectado</span>
                </small>
            `;
            banner.appendChild(indicator);
        }
    }
    
    // Función para verificar conectividad
    function checkConnectivity() {
        const dot = document.getElementById('connectivity-dot');
        const text = document.getElementById('connectivity-text');
        
        if (!dot || !text) return;
        
        fetch('/status?format=json', { 
            method: 'HEAD',
            cache: 'no-cache'
        })
        .then(response => {
            if (response.ok) {
                dot.className = 'status-indicator online';
                text.textContent = 'Conectado';
            } else {
                dot.className = 'status-indicator warning';
                text.textContent = 'Conexión lenta';
            }
        })
        .catch(() => {
            dot.className = 'status-indicator error';
            text.textContent = 'Sin conexión';
        });
    }
    
    // Mejorar las barras de progreso con animación
    function animateProgressBars() {
        const progressBars = document.querySelectorAll('.status-progress .progress-bar');
        progressBars.forEach((bar, index) => {
            const width = bar.style.width;
            bar.style.width = '0%';
            setTimeout(() => {
                bar.style.width = width;
            }, index * 200);
        });
    }
    
    // Añadir efectos de hover a las métricas
    function addMetricHoverEffects() {
        const metrics = document.querySelectorAll('.status-metric');
        metrics.forEach(metric => {
            metric.addEventListener('mouseenter', function() {
                this.style.transform = 'scale(1.05)';
                this.style.transition = 'transform 0.3s ease';
            });
            
            metric.addEventListener('mouseleave', function() {
                this.style.transform = 'scale(1)';
            });
        });
    }
    
    // Añadir contador de tiempo real
    function addRealTimeCounter() {
        const uptimeElement = document.querySelector('.status-metric h2.text-info');
        if (uptimeElement) {
            const startTime = Date.now();
            const initialUptime = uptimeElement.textContent;
            
            // Extraer horas y minutos iniciales
            const match = initialUptime.match(/(\d+)h (\d+)m/);
            if (match) {
                const initialHours = parseInt(match[1]);
                const initialMinutes = parseInt(match[2]);
                const initialTotalMinutes = initialHours * 60 + initialMinutes;
                
                setInterval(() => {
                    const elapsed = Math.floor((Date.now() - startTime) / 60000); // minutos transcurridos
                    const totalMinutes = initialTotalMinutes + elapsed;
                    const hours = Math.floor(totalMinutes / 60);
                    const minutes = totalMinutes % 60;
                    
                    uptimeElement.textContent = `${hours}h ${minutes}m`;
                }, 60000); // actualizar cada minuto
            }
        }
    }
    
    // Añadir notificaciones toast para cambios de estado
    function createToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast-notification toast-${type}`;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--status-bg-secondary);
            color: var(--status-text-primary);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            border-left: 4px solid var(--status-${type === 'error' ? 'danger' : type === 'warning' ? 'warning' : 'info'});
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 9999;
            transform: translateX(100%);
            transition: transform 0.3s ease;
        `;
        toast.textContent = message;
        
        document.body.appendChild(toast);
        
        // Animar entrada
        setTimeout(() => {
            toast.style.transform = 'translateX(0)';
        }, 100);
        
        // Auto-remover después de 3 segundos
        setTimeout(() => {
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, 3000);
    }
    
    // Monitorear cambios en métricas críticas
    let lastMetrics = {};
    function monitorMetrics() {
        fetch('/status?format=json')
        .then(response => response.json())
        .then(data => {
            // Verificar cambios en errores
            if (data.server && data.server.stability) {
                const currentErrors = data.server.stability.errors_24h;
                if (lastMetrics.errors !== undefined && currentErrors > lastMetrics.errors) {
                    createToast(`Nuevos errores detectados: ${currentErrors}`, 'warning');
                }
                lastMetrics.errors = currentErrors;
            }
            
            // Verificar estado de la base de datos
            if (data.database) {
                const currentDbStatus = data.database.status;
                if (lastMetrics.dbStatus !== undefined && currentDbStatus !== lastMetrics.dbStatus) {
                    const type = currentDbStatus === 'OK' ? 'success' : 'error';
                    createToast(`Estado de BD cambió a: ${currentDbStatus}`, type);
                }
                lastMetrics.dbStatus = currentDbStatus;
            }
        })
        .catch(error => {
            console.error('Error monitoreando métricas:', error);
        });
    }
    
    // Inicializar todas las mejoras
    addConnectivityIndicator();
    animateProgressBars();
    addMetricHoverEffects();
    addRealTimeCounter();
    
    // Verificar conectividad cada 10 segundos
    setInterval(checkConnectivity, 10000);
    checkConnectivity(); // verificación inicial
    
    // Monitorear métricas cada 30 segundos
    setInterval(monitorMetrics, 30000);
    monitorMetrics(); // verificación inicial
    
    // Añadir atajos de teclado
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + R para actualizar
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            const refreshBtn = document.querySelector('button[onclick="refreshStatus()"]');
            if (refreshBtn) {
                refreshBtn.click();
            }
        }
        
        // Ctrl/Cmd + J para ver JSON
        if ((e.ctrlKey || e.metaKey) && e.key === 'j') {
            e.preventDefault();
            window.open('/status?format=json', '_blank');
        }
    });
    
    // Mostrar información de atajos al hacer hover en botones
    const refreshBtn = document.querySelector('button[onclick="refreshStatus()"]');
    if (refreshBtn) {
        refreshBtn.title = 'Actualizar estado (Ctrl+R)';
    }
    
    const jsonBtn = document.querySelector('a[href="/status?format=json"]');
    if (jsonBtn) {
        jsonBtn.title = 'Ver JSON (Ctrl+J)';
    }
});

// Función global para refrescar con mejoras visuales
window.refreshStatus = function() {
    const button = event.target;
    const originalText = button.innerHTML;
    button.innerHTML = '<span class="status-loading"></span> Actualizando...';
    button.disabled = true;
    
    // Añadir efecto de pulsación
    button.style.transform = 'scale(0.95)';
    setTimeout(() => {
        button.style.transform = 'scale(1)';
    }, 150);
    
    setTimeout(() => {
        location.reload();
    }, 1000);
};