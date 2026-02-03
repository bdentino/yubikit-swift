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

struct MainTabView: View {
    @State private var selectedTab = 0

    var body: some View {
        Button("Test Notification") {
            let content = UNMutableNotificationContent()
            content.title = "Test"
            content.body = "Enter PIN"
            content.categoryIdentifier = "SIGNING_REQUEST"
            
            let request = UNNotificationRequest(
                identifier: UUID().uuidString,
                content: content,
                trigger: nil
            )
            
            UNUserNotificationCenter.current().add(request)
        }
        TabView(selection: $selectedTab) {
//            OATHListView()
//                .tabItem {
//                    Label("USB Codes", systemImage: "key.fill")
//                }
//                .tag(0)
//
//            PIVCertificatesView()
//                .tabItem {
//                    Label("PIV Certificates", systemImage: "doc.richtext")
//                }
//                .tag(1)
        }
    }
}

#Preview {
    MainTabView()
}
