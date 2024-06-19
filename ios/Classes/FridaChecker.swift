//
//  FridaChecker.swift
//  jailbreak_root_detection
//
//  Created by M on 23/1/2566 BE.
//

import Foundation


class FridaChecker {
    
    static func isFound() -> Bool {
        let fridaServerFile = FileManager.default.fileExists(atPath: "**/usr/bin/frida-server")
        let fridaAgentFile = FileManager.default.fileExists(atPath: "**/usr/bin/frida-agent")
        let fridaGadgetFile = FileManager.default.fileExists(atPath: "**/usr/bin/frida-gadget")
        let fridaInjectFile = FileManager.default.fileExists(atPath: "**/usr/bin/frida-inject")
        let fridaPortalFile = FileManager.default.fileExists(atPath: "**/usr/bin/frida-portal")
        let fridaAllFile = FileManager.default.fileExists(atPath: "**/usr/bin/frida-[a-z]**")

        let fridaLibraryFile = FileManager.default.fileExists(atPath: "**/usr/lib/libfrida-core.dylib")
        if fridaServerFile || fridaAgentFile || fridaGadgetFile || fridaInjectFile || fridaPortalFile || fridaAllFile || fridaLibraryFile {
            return true
        }
        return false
    }
}
