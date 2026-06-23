I am creating a test battery of certificate validation for Windows Operating System.
I need to test that the routines properly fail on subtle cryptographic bugs, either accidental or on purpose.

Create a single Python script that clones certificates and uses custom parameters and various anomalies in the certificates.
```
# We'll just store the cloned certificates in current user "Personal" store for now.
$CertStoreLocation = @{ CertStoreLocation = 'Cert:\CurrentUser\My' }
$MS_Root_Cert = Get-PfxCertificate -FilePath C:\Test\MSKernel32Root.cer
$Cloned_MS_Root_Cert = New-SelfSignedCertificate -CloneCert $MS_Root_Cert @CertStoreLocation
$MS_PCA_Cert = Get-PfxCertificate -FilePath C:\Test\MSKernel32PCA.cer
$Cloned_MS_PCA_Cert = New-SelfSignedCertificate -CloneCert $MS_PCA_Cert -Signer $Cloned_MS_Root_Cert @CertStoreLocation
$MS_Leaf_Cert = Get-PfxCertificate -FilePath C:\Test\MSKernel32Leaf.cer
$Cloned_MS_Leaf_Cert = New-SelfSignedCertificate -CloneCert $MS_Leaf_Cert -Signer $Cloned_MS_PCA_Cert @CertStoreLocation
# Create some sample code to practice signing on
Add-Type -TypeDefinition @'
public class Foo {
    public static void Main(string[] args) {
        System.Console.WriteLine("Hello, World!");
        System.Console.ReadKey();
    }
}
'@ -OutputAssembly C:\Test\HelloWorld.exe
# Validate that that HelloWorld.exe is not signed.
Get-AuthenticodeSignature -FilePath C:\Test\HelloWorld.exe
# Sign HelloWorld.exe with the cloned Microsoft leaf certificate.
Set-AuthenticodeSignature -Certificate $Cloned_MS_Leaf_Cert -FilePath C:\Test\HelloWorld.exe
# The certificate will not properly validate because the root certificate is not trusted.
# View the StatusMessage property to see the reason why Set-AuthenticodeSignature returned "UnknownError"
# "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider"
Get-AuthenticodeSignature -FilePath C:\Test\HelloWorld.exe | Format-List *
# Save the root certificate to disk and import it into the current user root store.
# Upon doing this, the HelloWorld.exe signature will validate properly.
Export-Certificate -Type CERT -FilePath C:\Test\MSKernel32Root_Cloned.cer -Cert $Cloned_MS_Root_Cert
Import-Certificate -FilePath C:\Test\MSKernel32Root_Cloned.cer -CertStoreLocation Cert:\CurrentUser\Root\
# You may need to start a new PowerShell process for the valid signature to take effect.
Get-AuthenticodeSignature -FilePath C:\Test\HelloWorld.exe
```
Keep a detailed log of all errors.
Create both Assemblies (dll) and (exe)
Attempt to load them in Powershell and track any faults to each exe with a uniue ID.
Build the folder that preserves any binary that faults and certificate parameters
