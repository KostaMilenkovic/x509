package implementation;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import sun.security.x509.X509CertImpl;
import x509.v3.GuiV3;



public class X509impl {
  private static KeyStore keyStore;
  private static Provider provider;
  private static String keyStorePassword = "keystore123";
  private static String keyStoreFileName = "keystore.ks";
  
    static {
        try {
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
           
        } catch (Exception e) {
            Logger.getLogger(X509impl.class.getName()).log(Level.SEVERE, null, e);
        }
    }

    public static KeyStore getKeyStore() {
        return keyStore;
    }

    public static void setKeyStore(KeyStore keyStore) {
        X509impl.keyStore = keyStore;
    }

    public static String getKeyStorePassword() {
        return keyStorePassword;
    }

    public static void setKeyStorePassword(String keyStorePassword) {
        X509impl.keyStorePassword = keyStorePassword;
    }

    public static String getKeyStoreFileName() {
        return keyStoreFileName;
    }

    public static void setKeyStoreFileName(String keyStoreFileName) {
        X509impl.keyStoreFileName = keyStoreFileName;
    }

  public static KeyStore loadKeyStore() throws Exception{
    InputStream readStream = new FileInputStream(keyStoreFileName);
    keyStore.load(readStream, keyStorePassword.toCharArray());
    readStream.close();
    return keyStore;
  }
  
    public static void storeKeyStore() throws Exception{
        OutputStream writeStream = new FileOutputStream(keyStoreFileName);
        keyStore.store(writeStream, keyStorePassword.toCharArray());
        writeStream.close();
    }
  
  //issuerDN is passed only if the certificate is not being self signed
    public static X509Certificate generateCertificate(GuiV3 guiV3,PublicKey publicKey, PrivateKey privateKey, boolean selfSigned, Principal issuerDN) throws Exception {
        X509Certificate result = null;
        X500Principal subjectPrincipal = new X500Principal("C="+guiV3.getSubjectCountry()+",ST="+guiV3.getSubjectState()+",L="+guiV3.getSubjectLocality()+",O="+guiV3.getSubjectOrganization()+",OU="+guiV3.getSubjectOrganizationUnit()+",CN="+guiV3.getSubjectCommonName());
        X500Principal issuerPrincipal = selfSigned?subjectPrincipal:new X500Principal(issuerDN.toString());
        
        ContentSigner contentSigner = new JcaContentSignerBuilder(guiV3.getPublicKeySignatureAlgorithm()).build(privateKey);
        JcaX509v3CertificateBuilder certificateBuilder =  new JcaX509v3CertificateBuilder(subjectPrincipal,new BigInteger(guiV3.getSerialNumber()) ,guiV3.getNotBefore(),guiV3.getNotAfter(),issuerPrincipal,publicKey);
        
        // Basic Constraints
        if(guiV3.isCritical(8)){
            BasicConstraints basicConstraints;
            if(guiV3.isCA()) // is CA or EndEntity
                basicConstraints = new BasicConstraints(Integer.parseInt(guiV3.getPathLen())); 
            else
                basicConstraints = new BasicConstraints(false);

            certificateBuilder.addExtension(Extension.basicConstraints, true, basicConstraints); 
            
        }
        
        if(guiV3.isCritical(1)){
            int keyUsageMask=0;
            if(guiV3.getKeyUsage()[0])keyUsageMask |= KeyUsage.digitalSignature;
            if(guiV3.getKeyUsage()[1])keyUsageMask |= KeyUsage.nonRepudiation;
            if(guiV3.getKeyUsage()[2])keyUsageMask |= KeyUsage.keyEncipherment;
            if(guiV3.getKeyUsage()[3])keyUsageMask |= KeyUsage.dataEncipherment;
            if(guiV3.getKeyUsage()[4])keyUsageMask |= KeyUsage.keyAgreement;
            if(guiV3.getKeyUsage()[5])keyUsageMask |= KeyUsage.keyCertSign;
            if(guiV3.getKeyUsage()[6])keyUsageMask |= KeyUsage.cRLSign;
            if(guiV3.getKeyUsage()[7])keyUsageMask |= KeyUsage.encipherOnly;
            if(guiV3.getKeyUsage()[8])keyUsageMask |= KeyUsage.decipherOnly;
            KeyUsage keyUsage = new KeyUsage(keyUsageMask);
            certificateBuilder.addExtension(Extension.keyUsage, true, keyUsage); 
            
        }

        
        if(guiV3.isCritical(3)){
            String[] alternativeName =  guiV3.getAlternativeName(5);
            if(alternativeName.length > 0) {
                List<GeneralName> names = new ArrayList();
                for(String name: alternativeName) {
                  GeneralName altName = new GeneralName(GeneralName.dNSName, name);
                  names.add(altName);
                }
                GeneralName [] listToArray = new GeneralName[names.size()];
                names.toArray(listToArray);
                GeneralNames subjectAltName = new GeneralNames(listToArray);
                certificateBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltName); 
            }
        }
        
        return new JcaX509CertificateConverter().setProvider(provider).getCertificate(certificateBuilder.build(contentSigner));
    }
  
    public static X509Certificate signCertificate(PKCS10CertificationRequest csr, X509Certificate certificateToSign, String issuer) throws Exception {
        
        KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(X509impl.getKeyStorePassword().toCharArray());
        KeyStore.PrivateKeyEntry caPrivateKeyEntry = (KeyStore.PrivateKeyEntry) X509impl.getKeyStore().getEntry(issuer, pp);
        X509Certificate caCertificate = (X509Certificate) X509impl.getKeyStore().getCertificate(issuer);
        PrivateKey caPrivateKey = caPrivateKeyEntry.getPrivateKey();
        
        String issuerSigAlgName = (caCertificate.getPublicKey().getAlgorithm().compareTo("DSA")==0)?"SHA1withDSA":caCertificate.getSigAlgName();
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(issuerSigAlgName);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivateKey.getEncoded());
        
        ContentSigner sigGen = null;
        String alg = caCertificate.getPublicKey().getAlgorithm();
        if((alg.contains("RSA"))||(alg.compareTo("RSA") == 0))
          sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(foo);
        else if((alg.contains("DSA"))||(alg.compareTo("DSA") == 0)) 
          sigGen = new BcDSAContentSignerBuilder(sigAlgId, digAlgId).build(foo);
        else if((alg.contains("EC"))||(alg.compareTo("EC") == 0)) 
          sigGen = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(foo);
        else throw new Exception("Invalid algorithm.");
  
        JcaX509v3CertificateBuilder certificateBuilder =  new JcaX509v3CertificateBuilder(caCertificate.getSubjectX500Principal(),certificateToSign.getSerialNumber(), certificateToSign.getNotBefore(), certificateToSign.getNotAfter(), certificateToSign.getSubjectX500Principal(),certificateToSign.getPublicKey());
        return new JcaX509CertificateConverter().setProvider(provider).getCertificate(certificateBuilder.build(sigGen));
    }
  
}
