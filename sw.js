// Service Worker untuk Sales Visit Push Notifications
// File: sw.js (letakkan di root directory)

const CACHE_NAME = 'sales-visit-v1.0';
const CACHE_URLS = [
    '/',
    '/sales_visit.php',
    '/index.php',
    '/notifications.php',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
];

// Install Event - Cache resources
self.addEventListener('install', function(event) {
    console.log('Service Worker installing...');
    
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                console.log('Caching app shell...');
                return cache.addAll(CACHE_URLS);
            })
            .then(function() {
                // Force activation of new service worker
                return self.skipWaiting();
            })
            .catch(function(error) {
                console.error('Cache failed:', error);
            })
    );
});

// Activate Event - Clean old caches
self.addEventListener('activate', function(event) {
    console.log('Service Worker activating...');
    
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(function() {
            // Take control of all pages
            return self.clients.claim();
        })
    );
});

// Fetch Event - Serve from cache, fallback to network
self.addEventListener('fetch', function(event) {
    // Skip cross-origin requests
    if (!event.request.url.startsWith(self.location.origin)) {
        return;
    }
    
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                // Return cached version or fetch from network
                return response || fetch(event.request);
            })
            .catch(function() {
                // Fallback for offline
                if (event.request.destination === 'document') {
                    return caches.match('/index.php');
                }
            })
    );
});

// Push Event - Handle incoming notifications
self.addEventListener('push', function(event) {
    console.log('Push notification received:', event);
    
    let notificationData = {
        title: 'Sales Visit Alert',
        body: 'Ada sales visit yang memerlukan perhatian Anda',
        icon: '/icons/icon-192.png',
        badge: '/icons/badge.png',
        image: '/icons/notification-banner.png',
        vibrate: [200, 100, 200],
        requireInteraction: true,
        tag: 'sales-visit-notification',
        data: {
            url: '/sales_visit.php',
            timestamp: Date.now()
        },
        actions: [
            {
                action: 'view',
                title: 'Lihat Detail',
                icon: '/icons/view.png'
            },
            {
                action: 'dismiss',
                title: 'Tutup',
                icon: '/icons/close.png'
            }
        ]
    };
    
    // Parse data from push event
    if (event.data) {
        try {
            const pushData = event.data.json();
            notificationData = { ...notificationData, ...pushData };
        } catch (error) {
            console.error('Error parsing push data:', error);
        }
    }
    
    event.waitUntil(
        self.registration.showNotification(notificationData.title, notificationData)
    );
});

// Notification Click Event
self.addEventListener('notificationclick', function(event) {
    console.log('Notification clicked:', event);
    
    event.notification.close();
    
    const action = event.action;
    const notificationData = event.notification.data || {};
    
    if (action === 'view') {
        // Open sales visit page
        event.waitUntil(
            clients.openWindow('/sales_visit.php?from=notification')
        );
    } else if (action === 'dismiss') {
        // Just close - no action needed
        console.log('Notification dismissed');
    } else {
        // Default click - open appropriate page
        const targetUrl = notificationData.url || '/sales_visit.php';
        
        event.waitUntil(
            clients.matchAll({ type: 'window' }).then(function(clientList) {
                // Check if sales visit page is already open
                for (let client of clientList) {
                    if (client.url.includes('sales_visit.php') && 'focus' in client) {
                        return client.focus();
                    }
                }
                
                // Open new window if not found
                if (clients.openWindow) {
                    return clients.openWindow(targetUrl);
                }
            })
        );
    }
    
    // Track notification interaction
    trackNotificationClick(event.notification.tag, action);
});

// Background Sync Event (untuk offline functionality)
self.addEventListener('sync', function(event) {
    console.log('Background sync triggered:', event.tag);
    
    if (event.tag === 'notification-check') {
        event.waitUntil(
            checkForNewNotifications()
        );
    }
});

// Helper function untuk check notifications
function checkForNewNotifications() {
    return fetch('/check_notifications.php?key=your_secret_cron_key')
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            if (data.success && data.hasNewNotifications) {
                return self.registration.showNotification(
                    'Sales Visit Update',
                    {
                        body: `Anda memiliki ${data.due_today + data.overdue} notifikasi baru`,
                        icon: '/icons/icon-192.png',
                        badge: '/icons/badge.png',
                        tag: 'background-check',
                        data: {
                            url: '/notifications.php'
                        }
                    }
                );
            }
        })
        .catch(function(error) {
            console.log('Background notification check failed:', error);
        });
}

// Helper function untuk track clicks
function trackNotificationClick(tag, action) {
    // Send analytics atau log ke server
    fetch('/track_notification.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            tag: tag,
            action: action || 'default',
            timestamp: Date.now()
        })
    }).catch(function(error) {
        console.log('Failed to track notification click:', error);
    });
}

// Message Event - Communication dengan main thread
self.addEventListener('message', function(event) {
    console.log('Service Worker received message:', event.data);
    
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
    
    if (event.data && event.data.type === 'CHECK_NOTIFICATIONS') {
        checkForNewNotifications();
    }
});

// Error handling
self.addEventListener('error', function(error) {
    console.error('Service Worker error:', error);
});

self.addEventListener('unhandledrejection', function(event) {
    console.error('Service Worker unhandled rejection:', event.reason);
});

console.log('Service Worker script loaded successfully');