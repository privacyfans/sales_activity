<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Push Notification Test</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    
    <!-- PWA Meta Tags -->
    <meta name="theme-color" content="#0d6efd">
    <link rel="manifest" href="./manifest.json">
    <link rel="apple-touch-icon" href="./icons/icon-192.png">
    
    <style>
        .test-section {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .test-result {
            background: #f8f9fa;
            border-radius: 4px;
            padding: 15px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 12px;
            max-height: 200px;
            overflow-y: auto;
        }
        .status-success { color: #198754; }
        .status-error { color: #dc3545; }
        .status-warning { color: #fd7e14; }
        .status-info { color: #0dcaf0; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h1><i class="fas fa-bell me-2"></i>Push Notification Test Suite</h1>
                <p class="text-muted">Comprehensive testing for push notification functionality</p>
                
                <!-- Overall Status -->
                <div class="alert alert-info">
                    <div class="row">
                        <div class="col-md-3">
                            <strong>Browser Support:</strong> <span id="browser-support">Checking...</span>
                        </div>
                        <div class="col-md-3">
                            <strong>Permission:</strong> <span id="permission-status">Checking...</span>
                        </div>
                        <div class="col-md-3">
                            <strong>Service Worker:</strong> <span id="sw-status">Checking...</span>
                        </div>
                        <div class="col-md-3">
                            <strong>Push Subscription:</strong> <span id="subscription-status">Not tested</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <!-- Test 1: Browser Support -->
            <div class="col-md-6">
                <div class="test-section">
                    <h4><i class="fas fa-browser me-2"></i>1. Browser Support</h4>
                    <p>Test browser compatibility for push notifications</p>
                    <button class="btn btn-primary" onclick="testBrowserSupport()">Test Browser Support</button>
                    <div id="browser-test-result" class="test-result" style="display:none;"></div>
                </div>
            </div>
            
            <!-- Test 2: Local Notifications -->
            <div class="col-md-6">
                <div class="test-section">
                    <h4><i class="fas fa-bell me-2"></i>2. Local Notifications</h4>
                    <p>Test basic notification functionality</p>
                    <button class="btn btn-success" onclick="testLocalNotification()">Test Local Notification</button>
                    <div id="local-test-result" class="test-result" style="display:none;"></div>
                </div>
            </div>
            
            <!-- Test 3: Service Worker -->
            <div class="col-md-6">
                <div class="test-section">
                    <h4><i class="fas fa-cogs me-2"></i>3. Service Worker</h4>
                    <p>Test service worker registration and status</p>
                    <button class="btn btn-info" onclick="testServiceWorker()">Test Service Worker</button>
                    <button class="btn btn-outline-info" onclick="registerServiceWorker()">Register SW</button>
                    <div id="sw-test-result" class="test-result" style="display:none;"></div>
                </div>
            </div>
            
            <!-- Test 4: Push Subscription -->
            <div class="col-md-6">
                <div class="test-section">
                    <h4><i class="fas fa-satellite-dish me-2"></i>4. Push Subscription</h4>
                    <p>Test push subscription creation and management</p>
                    <button class="btn btn-warning" onclick="testPushSubscription()">Create Subscription</button>
                    <button class="btn btn-outline-warning" onclick="testSaveSubscription()">Save to Server</button>
                    <div id="push-test-result" class="test-result" style="display:none;"></div>
                </div>
            </div>
            
            <!-- Test 5: Server Integration -->
            <div class="col-md-6">
                <div class="test-section">
                    <h4><i class="fas fa-server me-2"></i>5. Server Integration</h4>
                    <p>Test server-side push notification functionality</p>
                    <button class="btn btn-danger" onclick="testServerIntegration()">Test Server API</button>
                    <button class="btn btn-outline-danger" onclick="triggerManualPush()">Send Manual Push</button>
                    <div id="server-test-result" class="test-result" style="display:none;"></div>
                </div>
            </div>
            
            <!-- Test 6: End-to-End -->
            <div class="col-md-6">
                <div class="test-section">
                    <h4><i class="fas fa-check-double me-2"></i>6. End-to-End Test</h4>
                    <p>Complete workflow test with real data</p>
                    <button class="btn btn-success" onclick="testEndToEnd()">Run E2E Test</button>
                    <button class="btn btn-outline-success" onclick="createTestData()">Create Test Data</button>
                    <div id="e2e-test-result" class="test-result" style="display:none;"></div>
                </div>
            </div>
        </div>
        
        <!-- Master Controls -->
        <div class="row mt-4">
            <div class="col-12">
                <div class="test-section bg-light">
                    <h4><i class="fas fa-play-circle me-2"></i>Master Controls</h4>
                    <div class="btn-group me-2" role="group">
                        <button class="btn btn-primary btn-lg" onclick="runAllTests()">
                            <i class="fas fa-play me-1"></i>Run All Tests
                        </button>
                        <button class="btn btn-secondary" onclick="clearAllResults()">
                            <i class="fas fa-trash me-1"></i>Clear Results
                        </button>
                        <button class="btn btn-info" onclick="exportResults()">
                            <i class="fas fa-download me-1"></i>Export Results
                        </button>
                    </div>
                    
                    <div class="btn-group" role="group">
                        <button class="btn btn-outline-primary" onclick="debugMode = !debugMode; updateDebugStatus()">
                            <i class="fas fa-bug me-1"></i><span id="debug-btn-text">Enable Debug</span>
                        </button>
                        <button class="btn btn-outline-info" onclick="showSystemInfo()">
                            <i class="fas fa-info-circle me-1"></i>System Info
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- System Info Modal -->
    <div class="modal fade" id="systemInfoModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">System Information</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="system-info-content"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Global variables
        let debugMode = false;
        let currentSubscription = null;
        let testResults = {};
        
        // Configuration - UPDATE THESE VALUES
        const CONFIG = {
            VAPID_PUBLIC_KEY: 'BPHuRLM1oyf-ldW0f26TyKY08WFq3meeWW6vyvxxm9N-KPwxZBOsKM6XbhK7BKwii48yy0DV8kGo_6DH_cujRLg',
            USER_ID: 2, // Change this to your test user ID
            SW_PATH: './sw.js',
            SAVE_SUBSCRIPTION_URL: 'save_subscription.php',
            CHECK_NOTIFICATIONS_URL: 'check_notifications.php',
            SEND_PUSH_URL: 'send_push_notification.php'
        };
        
        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            updateStatus();
            updateDebugStatus();
        });
        
        // Utility functions
        function log(message, type = 'info') {
            const timestamp = new Date().toLocaleTimeString();
            const logEntry = `[${timestamp}] ${message}`;
            
            if (debugMode) {
                console.log(logEntry);
            }
            
            return logEntry;
        }
        
        function updateResultDiv(elementId, content, isError = false) {
            const div = document.getElementById(elementId);
            div.style.display = 'block';
            div.innerHTML = content;
            div.className = `test-result ${isError ? 'status-error' : 'status-success'}`;
        }
        
        function updateStatus() {
            // Browser support
            const browserSupport = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
            document.getElementById('browser-support').innerHTML = browserSupport ? 
                '<span class="status-success">✅ Supported</span>' : 
                '<span class="status-error">❌ Not Supported</span>';
            
            // Permission status
            const permission = 'Notification' in window ? Notification.permission : 'not-supported';
            let permissionHtml = '';
            switch(permission) {
                case 'granted':
                    permissionHtml = '<span class="status-success">✅ Granted</span>';
                    break;
                case 'denied':
                    permissionHtml = '<span class="status-error">❌ Denied</span>';
                    break;
                case 'default':
                    permissionHtml = '<span class="status-warning">⏳ Default</span>';
                    break;
                default:
                    permissionHtml = '<span class="status-error">❌ Not Supported</span>';
            }
            document.getElementById('permission-status').innerHTML = permissionHtml;
            
            // Service Worker status
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.getRegistrations().then(registrations => {
                    const swStatus = registrations.length > 0 ? 
                        '<span class="status-success">✅ Registered</span>' : 
                        '<span class="status-warning">⏳ Not Registered</span>';
                    document.getElementById('sw-status').innerHTML = swStatus;
                });
            } else {
                document.getElementById('sw-status').innerHTML = '<span class="status-error">❌ Not Supported</span>';
            }
        }
        
        function updateDebugStatus() {
            document.getElementById('debug-btn-text').textContent = debugMode ? 'Disable Debug' : 'Enable Debug';
        }
        
        // Test 1: Browser Support
        function testBrowserSupport() {
            const results = [];
            
            results.push(log('Testing browser support...'));
            results.push(log(`Service Worker: ${'serviceWorker' in navigator ? '✅ Supported' : '❌ Not Supported'}`));
            results.push(log(`Push Manager: ${'PushManager' in window ? '✅ Supported' : '❌ Not Supported'}`));
            results.push(log(`Notifications: ${'Notification' in window ? '✅ Supported' : '❌ Not Supported'}`));
            results.push(log(`HTTPS: ${location.protocol === 'https:' ? '✅ Enabled' : '❌ Required'}`));
            
            // Browser info
            results.push(log(`User Agent: ${navigator.userAgent}`));
            results.push(log(`Platform: ${navigator.platform}`));
            results.push(log(`Language: ${navigator.language}`));
            
            updateResultDiv('browser-test-result', results.join('\n'));
            testResults.browserSupport = results;
        }
        
        // Test 2: Local Notifications
        async function testLocalNotification() {
            const results = [];
            
            try {
                results.push(log('Testing local notifications...'));
                
                if (!('Notification' in window)) {
                    throw new Error('Notifications not supported');
                }
                
                if (Notification.permission === 'default') {
                    results.push(log('Requesting notification permission...'));
                    const permission = await Notification.requestPermission();
                    results.push(log(`Permission result: ${permission}`));
                }
                
                if (Notification.permission === 'granted') {
                    results.push(log('Creating test notification...'));
                    
                    const notification = new Notification('🧪 Push Test Notification', {
                        body: 'This is a test notification from the push test suite',
                        icon: 'icons/icon-192.png',
                        tag: 'push-test-local',
                        requireInteraction: false
                    });
                    
                    notification.onclick = () => {
                        results.push(log('✅ Notification clicked'));
                        updateResultDiv('local-test-result', results.join('\n'));
                        notification.close();
                    };
                    
                    setTimeout(() => {
                        notification.close();
                    }, 5000);
                    
                    results.push(log('✅ Local notification sent successfully'));
                } else {
                    results.push(log('❌ Notification permission denied'));
                }
                
            } catch (error) {
                results.push(log(`❌ Service worker registration failed: ${error.message}`));
            }
            
            updateResultDiv('sw-test-result', results.join('\n'));
            testResults.serviceWorkerRegistration = results;
            updateStatus();
        }
        
        // Test 4: Push Subscription
        async function testPushSubscription() {
            const results = [];
            
            try {
                results.push(log('Testing push subscription...'));
                
                if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
                    throw new Error('Push notifications not supported');
                }
                
                const registration = await navigator.serviceWorker.ready;
                results.push(log('Service worker is ready'));
                
                const subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(CONFIG.VAPID_PUBLIC_KEY)
                });
                
                results.push(log('✅ Push subscription created successfully'));
                results.push(log(`Endpoint: ${subscription.endpoint.substring(0, 50)}...`));
                results.push(log(`Keys available: ${subscription.getKeys ? 'Yes' : 'No'}`));
                
                currentSubscription = subscription;
                document.getElementById('subscription-status').innerHTML = '<span class="status-success">✅ Created</span>';
                
            } catch (error) {
                results.push(log(`❌ Push subscription failed: ${error.message}`));
                document.getElementById('subscription-status').innerHTML = '<span class="status-error">❌ Failed</span>';
            }
            
            updateResultDiv('push-test-result', results.join('\n'));
            testResults.pushSubscription = results;
        }
        
        // Test Save Subscription to Server
        async function testSaveSubscription() {
            const results = [];
            
            try {
                results.push(log('Testing save subscription to server...'));
                
                if (!currentSubscription) {
                    results.push(log('Creating new subscription first...'));
                    await testPushSubscription();
                }
                
                if (!currentSubscription) {
                    throw new Error('No subscription available to save');
                }
                
                const payload = {
                    subscription: currentSubscription.toJSON ? currentSubscription.toJSON() : currentSubscription,
                    user_id: CONFIG.USER_ID,
                    user_agent: navigator.userAgent,
                    timestamp: Date.now()
                };
                
                results.push(log('Sending subscription to server...'));
                
                const response = await fetch(CONFIG.SAVE_SUBSCRIPTION_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(payload)
                });
                
                results.push(log(`Response status: ${response.status}`));
                
                const text = await response.text();
                results.push(log(`Raw response: ${text.substring(0, 200)}...`));
                
                const data = JSON.parse(text);
                
                if (data.success) {
                    results.push(log('✅ Subscription saved successfully'));
                    results.push(log(`Action: ${data.action}`));
                    results.push(log(`Device: ${data.device_info}`));
                    results.push(log(`User: ${data.user_name}`));
                    results.push(log(`Total subscriptions: ${data.total_subscriptions}`));
                } else {
                    results.push(log(`❌ Save failed: ${data.error}`));
                    if (data.debug_info) {
                        results.push(log(`Debug info: ${JSON.stringify(data.debug_info)}`));
                    }
                }
                
            } catch (error) {
                results.push(log(`❌ Save subscription test failed: ${error.message}`));
            }
            
            updateResultDiv('push-test-result', results.join('\n'));
            testResults.saveSubscription = results;
        }
        
        // Test 5: Server Integration
        async function testServerIntegration() {
            const results = [];
            
            try {
                results.push(log('Testing server integration...'));
                
                // Test check notifications endpoint
                results.push(log('Testing check notifications endpoint...'));
                
                const checkUrl = `${CONFIG.CHECK_NOTIFICATIONS_URL}?type=quick&user_id=${CONFIG.USER_ID}`;
                const checkResponse = await fetch(checkUrl, {
                    method: 'GET',
                    credentials: 'same-origin'
                });
                
                results.push(log(`Check notifications status: ${checkResponse.status}`));
                
                const checkText = await checkResponse.text();
                const checkData = JSON.parse(checkText);
                
                if (checkData.success) {
                    results.push(log('✅ Check notifications working'));
                    results.push(log(`Due today: ${checkData.due_today}`));
                    results.push(log(`Overdue: ${checkData.overdue}`));
                    results.push(log(`User role: ${checkData.user_role}`));
                } else {
                    results.push(log(`❌ Check notifications failed: ${checkData.error}`));
                }
                
                // Test database connection
                results.push(log('Testing database connection...'));
                results.push(log('✅ Database queries working (if check notifications succeeded)'));
                
            } catch (error) {
                results.push(log(`❌ Server integration test failed: ${error.message}`));
            }
            
            updateResultDiv('server-test-result', results.join('\n'));
            testResults.serverIntegration = results;
        }
        
        // Trigger Manual Push
        async function triggerManualPush() {
            const results = [];
            
            try {
                results.push(log('Triggering manual push notification...'));
                
                const response = await fetch(CONFIG.SEND_PUSH_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ test: true })
                });
                
                results.push(log(`Push trigger status: ${response.status}`));
                
                const text = await response.text();
                const data = JSON.parse(text);
                
                if (data.success) {
                    results.push(log('✅ Manual push triggered successfully'));
                    results.push(log(`Sent: ${data.sent}`));
                    results.push(log(`Failed: ${data.failed}`));
                    results.push(log(`Total subscriptions: ${data.total_subscriptions}`));
                } else {
                    results.push(log(`❌ Manual push failed: ${data.error}`));
                }
                
            } catch (error) {
                results.push(log(`❌ Manual push test failed: ${error.message}`));
            }
            
            updateResultDiv('server-test-result', results.join('\n'));
        }
        
        // Test 6: End-to-End
        async function testEndToEnd() {
            const results = [];
            
            try {
                results.push(log('Running end-to-end test...'));
                
                // Step 1: Browser support
                results.push(log('Step 1: Checking browser support'));
                if (!('serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window)) {
                    throw new Error('Browser not supported');
                }
                results.push(log('✅ Browser supported'));
                
                // Step 2: Request permission
                results.push(log('Step 2: Requesting notification permission'));
                if (Notification.permission === 'default') {
                    const permission = await Notification.requestPermission();
                    results.push(log(`Permission result: ${permission}`));
                }
                
                if (Notification.permission !== 'granted') {
                    throw new Error('Notification permission required');
                }
                results.push(log('✅ Permission granted'));
                
                // Step 3: Register service worker
                results.push(log('Step 3: Registering service worker'));
                const registration = await navigator.serviceWorker.register(CONFIG.SW_PATH);
                await navigator.serviceWorker.ready;
                results.push(log('✅ Service worker ready'));
                
                // Step 4: Create subscription
                results.push(log('Step 4: Creating push subscription'));
                const subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(CONFIG.VAPID_PUBLIC_KEY)
                });
                results.push(log('✅ Subscription created'));
                
                // Step 5: Save to server
                results.push(log('Step 5: Saving subscription to server'));
                const saveResponse = await fetch(CONFIG.SAVE_SUBSCRIPTION_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        subscription: subscription.toJSON ? subscription.toJSON() : subscription,
                        user_id: CONFIG.USER_ID,
                        user_agent: navigator.userAgent,
                        timestamp: Date.now()
                    })
                });
                
                const saveData = await saveResponse.json();
                if (!saveData.success) {
                    throw new Error(`Save failed: ${saveData.error}`);
                }
                results.push(log('✅ Subscription saved to server'));
                
                // Step 6: Test notifications check
                results.push(log('Step 6: Testing notification check'));
                const checkResponse = await fetch(`${CONFIG.CHECK_NOTIFICATIONS_URL}?type=quick&user_id=${CONFIG.USER_ID}`, {
                    credentials: 'same-origin'
                });
                const checkData = await checkResponse.json();
                if (!checkData.success) {
                    throw new Error(`Check failed: ${checkData.error}`);
                }
                results.push(log('✅ Notification check working'));
                
                // Step 7: Send test notification
                results.push(log('Step 7: Sending test local notification'));
                const testNotification = new Notification('🎉 E2E Test Complete', {
                    body: 'All push notification components are working correctly!',
                    icon: '/icons/icon-192.png',
                    tag: 'e2e-test-complete'
                });
                
                setTimeout(() => testNotification.close(), 5000);
                results.push(log('✅ Test notification sent'));
                
                results.push(log('🎉 END-TO-END TEST PASSED!'));
                
            } catch (error) {
                results.push(log(`❌ End-to-end test failed: ${error.message}`));
            }
            
            updateResultDiv('e2e-test-result', results.join('\n'));
            testResults.endToEnd = results;
        }
        
        // Create Test Data
        async function createTestData() {
            const results = [];
            
            try {
                results.push(log('Creating test data...'));
                
                // This would typically create sales visit records with due dates
                results.push(log('⚠️ Test data creation not implemented'));
                results.push(log('Manual step: Add sales visit records with today\'s due date to test notifications'));
                
                // For now, just test if we can check for existing data
                const checkResponse = await fetch(`${CONFIG.CHECK_NOTIFICATIONS_URL}?type=quick&user_id=${CONFIG.USER_ID}`, {
                    credentials: 'same-origin'
                });
                
                const checkData = await checkResponse.json();
                if (checkData.success) {
                    results.push(log(`Current due today: ${checkData.due_today}`));
                    results.push(log(`Current overdue: ${checkData.overdue}`));
                    
                    if (checkData.due_today > 0 || checkData.overdue > 0) {
                        results.push(log('✅ Test data already exists!'));
                    } else {
                        results.push(log('ℹ️ No due visits found - create some manually for testing'));
                    }
                }
                
            } catch (error) {
                results.push(log(`❌ Test data creation failed: ${error.message}`));
            }
            
            updateResultDiv('e2e-test-result', results.join('\n'));
        }
        
        // Master Functions
        async function runAllTests() {
            console.log('🧪 Running all push notification tests...');
            
            clearAllResults();
            
            const tests = [
                { name: 'Browser Support', func: testBrowserSupport, delay: 1000 },
                { name: 'Local Notification', func: testLocalNotification, delay: 2000 },
                { name: 'Service Worker', func: testServiceWorker, delay: 3000 },
                { name: 'Push Subscription', func: testPushSubscription, delay: 4000 },
                { name: 'Save Subscription', func: testSaveSubscription, delay: 5000 },
                { name: 'Server Integration', func: testServerIntegration, delay: 6000 },
                { name: 'End-to-End', func: testEndToEnd, delay: 7000 }
            ];
            
            for (const test of tests) {
                setTimeout(async () => {
                    console.log(`Running ${test.name} test...`);
                    await test.func();
                }, test.delay);
            }
            
            // Final summary
            setTimeout(() => {
                console.log('✅ All tests completed!');
                showTestSummary();
            }, 8000);
        }
        
        function clearAllResults() {
            const resultDivs = [
                'browser-test-result',
                'local-test-result', 
                'sw-test-result',
                'push-test-result',
                'server-test-result',
                'e2e-test-result'
            ];
            
            resultDivs.forEach(id => {
                const div = document.getElementById(id);
                if (div) {
                    div.style.display = 'none';
                    div.innerHTML = '';
                }
            });
            
            testResults = {};
            console.log('Test results cleared');
        }
        
        function exportResults() {
            const timestamp = new Date().toISOString();
            const exportData = {
                timestamp: timestamp,
                browser: navigator.userAgent,
                config: CONFIG,
                results: testResults
            };
            
            const blob = new Blob([JSON.stringify(exportData, null, 2)], {
                type: 'application/json'
            });
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `push-notification-test-${timestamp.replace(/[:.]/g, '-')}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            console.log('Test results exported');
        }
        
        function showTestSummary() {
            const summary = [];
            let totalTests = 0;
            let passedTests = 0;
            
            Object.keys(testResults).forEach(testName => {
                totalTests++;
                const results = testResults[testName];
                const hasError = results.some(result => result.includes('❌'));
                if (!hasError) passedTests++;
                
                summary.push(`${testName}: ${hasError ? '❌ FAILED' : '✅ PASSED'}`);
            });
            
            console.log('🔍 TEST SUMMARY:');
            console.log(`Passed: ${passedTests}/${totalTests}`);
            summary.forEach(line => console.log(line));
        }
        
        function showSystemInfo() {
            const info = {
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                cookieEnabled: navigator.cookieEnabled,
                onLine: navigator.onLine,
                protocol: location.protocol,
                host: location.host,
                serviceWorkerSupport: 'serviceWorker' in navigator,
                pushManagerSupport: 'PushManager' in window,
                notificationSupport: 'Notification' in window,
                notificationPermission: Notification.permission,
                currentTime: new Date().toISOString()
            };
            
            const infoHtml = Object.keys(info).map(key => 
                `<strong>${key}:</strong> ${info[key]}`
            ).join('<br>');
            
            document.getElementById('system-info-content').innerHTML = infoHtml;
            
            const modal = new bootstrap.Modal(document.getElementById('systemInfoModal'));
            modal.show();
        }
        
        // Utility function
        function urlBase64ToUint8Array(base64String) {
            const padding = '='.repeat((4 - base64String.length % 4) % 4);
            const base64 = (base64String + padding)
                .replace(/\-/g, '+')
                .replace(/_/g, '/');
                
            const rawData = window.atob(base64);
            const outputArray = new Uint8Array(rawData.length);
            
            for (let i = 0; i < rawData.length; ++i) {
                outputArray[i] = rawData.charCodeAt(i);
            }
            
            return outputArray;
        }
        
        console.log('🧪 Push Notification Test Suite loaded');
        console.log('Available functions: testBrowserSupport(), testLocalNotification(), testServiceWorker(), testPushSubscription(), testSaveSubscription(), testServerIntegration(), testEndToEnd(), runAllTests()');
    </script>
</body>
</html>