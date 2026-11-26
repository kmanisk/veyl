# Native Windows preview only. No install, service, policy, or remote changes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $hostTarget = (rustc -vV | Select-String '^host: ').Line.Substring(6)
    if ($LASTEXITCODE -ne 0 -or $hostTarget -ne 'x86_64-pc-windows-msvc') {
        throw 'Use the native x86_64-pc-windows-msvc Rust toolchain and Windows SDK.'
    }
    cargo build --locked --target x86_64-pc-windows-msvc --bin veyl --bin mcp-gateway
    if ($LASTEXITCODE -ne 0) { throw 'Native Windows build failed' }
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { 'target' }
    $bin = (Resolve-Path (Join-Path $target 'x86_64-pc-windows-msvc/debug/mcp-gateway.exe')).Path
    $info = & $bin platform | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $info.os -ne 'windows') { throw 'Wrong native target' }
    $frames = @(
        '{"jsonrpc":"2.0","id":0,"method":"tools/list"}',
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"windows-native","version":"1"},"capabilities":{}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"platform_info","arguments":{}}}',
        '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec_command","arguments":{"command":"exit 99"}}}',
        '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"file"}}}'
    )
    $raw = $frames | & $bin platform-probe
    if ($LASTEXITCODE -ne 0) { throw 'Native MCP probe failed' }
    $responses = @($raw | ForEach-Object { $_ | ConvertFrom-Json })
    if ($responses.Count -ne 6) { throw 'Wrong response count' }
    if ($responses[0].error.code -ne -32000 -or $responses[1].result.protocolVersion -ne '2025-11-25') { throw 'MCP lifecycle failure' }
    $tools = @($responses[2].result.tools)
    if ($tools.Count -ne 1 -or $tools[0].name -ne 'platform_info') { throw 'Unexpected tool authority' }
    if ($responses[3].result.isError -or ($responses[3].result.content[0].text | ConvertFrom-Json).os -ne 'windows') { throw 'Platform report failure' }
    if ($responses[4].error.code -ne -32602 -or $responses[5].error.code -ne -32602) { throw 'Unsafe tool exposed' }
    Write-Output 'WINDOWS_NATIVE_PLATFORM_PROBE_PASS'
    Get-FileHash -Algorithm SHA256 $bin
} finally { Pop-Location }
