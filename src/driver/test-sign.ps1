# test-sign.ps1 — finds or creates the 9NS test code-signing cert and
# prints its thumbprint. Used by build.cmd before the VC environment is loaded
# (vcvars breaks the PowerShell Cert: drive).

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq 'CN=9NS Test Signing' -and $_.HasPrivateKey } |
    Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=9NS Test Signing' `
        -CertStoreLocation Cert:\CurrentUser\My
}

$cert.Thumbprint
