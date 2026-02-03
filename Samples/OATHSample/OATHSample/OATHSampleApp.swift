// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import SwiftUI
import UserNotifications

@main
struct OATHSampleApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    var body: some Scene {
        WindowGroup {
            MainTabView()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        print("!!! applicationDidFinishLaunching called")
        UNUserNotificationCenter.current().delegate = self
        requestNotificationPermission()
        setupNotificationCategories()
        setupDarwinNotificationListener()
    }
    
    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                print("Notification permission error: \(error)")
            }
            print("Notification permission granted: \(granted)")
        }
    }
    
    func setupDarwinNotificationListener() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passRetained(self).toOpaque()
        
        CFNotificationCenterAddObserver(
            center,
            observer,
            { (center, observer, name, object, userInfo) in
                guard let observer = observer else { return }
                let appDelegate = Unmanaged<AppDelegate>.fromOpaque(observer).takeUnretainedValue()
                
                DispatchQueue.main.async {
                    appDelegate.handleExtensionNotificationRequest()
                }
            },
            "sh.bjd.Authenticator.showNotification" as CFString,
            nil,
            .deliverImmediately
        )
        
        print("✅ Listening for extension notification requests")
    }
    
    func handleExtensionNotificationRequest() {
        print("🔔 Extension requested notification")
        
        // Read data from App Group
        guard let sharedDefaults = UserDefaults(suiteName: "group.sh.bjd.Authenticator"),
              let body = sharedDefaults.string(forKey: "notificationBody") else {
            return
        }
        
        let category = sharedDefaults.string(forKey: "notificationCategory") ?? ""
        
        // Main app sends the notification
        let content = UNMutableNotificationContent()
        content.title = "Authenticator"
        content.body = body
        content.categoryIdentifier = category
        content.sound = .default
        
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("❌ Error: \(error)")
            } else {
                print("✅ Notification sent from main app")
            }
        }
    }
    
    func setupNotificationCategories() {
        let enterPINAction = UNTextInputNotificationAction(
            identifier: "ENTER_PIN",
            title: "Sign",
            options: [],
            textInputButtonTitle: "Submit",
            textInputPlaceholder: "Enter PIN"
        )
        
        let cancelAction = UNNotificationAction(
            identifier: "CANCEL",
            title: "Cancel",
            options: .destructive
        )
        
        let category = UNNotificationCategory(
            identifier: "SIGNING_REQUEST",
            actions: [enterPINAction, cancelAction],
            intentIdentifiers: [],
            options: []
        )
        
        UNUserNotificationCenter.current().setNotificationCategories([category])
        print("!!! categories registered")
    }
    
    // Show notification even when app is in foreground
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        print("!!! willPresent called")
        completionHandler([.banner, .sound])
    }
    
    // Handle notification response
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        print("!!! didReceive called with action: \(response.actionIdentifier)")
        let userInfo = response.notification.request.content.userInfo
        
        guard let userDefaults = UserDefaults(suiteName: "group.sh.bjd.Authenticator") else {
            print("Failed to access shared UserDefaults")
            completionHandler()
            return
        }
        
        switch response.actionIdentifier {
        case "ENTER_PIN":
            if let textResponse = response as? UNTextInputNotificationResponse {
                let pin = textResponse.userText
                print("PIN entered: \(pin.count) characters")
                
                // Store PIN for the extension to use
                userDefaults.setValue("garbage", forKey: "signedData")
                userDefaults.synchronize()
            }
            
        case "CANCEL":
            print("User cancelled signing")
            userDefaults.set(true, forKey: "canceledByUser")
            userDefaults.synchronize()
            
        case UNNotificationDefaultActionIdentifier:
            // User tapped the notification itself (not an action)
            print("Notification tapped")
            
        case UNNotificationDismissActionIdentifier:
            // User dismissed the notification
            print("Notification dismissed")
            userDefaults.set(true, forKey: "canceledByUser")
            userDefaults.synchronize()
            
        default:
            break
        }
        
        completionHandler()
    }
}
