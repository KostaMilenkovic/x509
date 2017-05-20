package util;

import implementation.MyCode;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import model.UIParameters;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.security.x509.X509CertImpl;import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.security.x509.X509CertImpl;


public class X509Utils {
  private static KeyStore keyStore;
  private static X509Utils instance = null;
  private static String keyStorePassword = "123";
  private static String keyStoreFileName = "keystore";
  
  public X509Utils() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    keyStore = KeyStore.getInstance("BKS", "BC");
  }
  
  public KeyStore loadKeyStore() {
    try {
      keyStore = X509Utils.getInstance().getKeyStore();
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    }
    
    try {
      InputStream readStream = new FileInputStream(X509Utils.getKeyStoreFileName());
      keyStore.load(readStream, X509Utils.getKeyStorePassword().toCharArray());
      readStream.close();
    } catch (Exception ex) {
      try {
        keyStore.load(null,null);
      } catch (Exception ex1) {
        Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex1);
      }
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return keyStore;
  }
  
  public void storeKeyStore() {
    OutputStream writeStream;
    try {
      writeStream = new FileOutputStream(keyStoreFileName);
      keyStore.store(writeStream, keyStorePassword.toCharArray());
      writeStream.close();
    } catch (Exception ex) {
      Logger.getLogger(X509Utils.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  //issuerDN is passed only if the certificate is not being self signed
  public X509Certificate generateCertificate(UIParameters uiParams, PublicKey pubKey, PrivateKey privKey, boolean selfSigned, Principal issuerDN) throws GeneralSecurityException, IOException, Exception {
    X509Certificate result = null;
    X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
    X500Principal xp = new X500Principal(uiParams.getDn());
    
    certGen.setSerialNumber(uiParams.getSerialNumber());
    certGen.setIssuerDN(selfSigned?xp:new X500Principal(issuerDN.toString()));
    certGen.setNotBefore(uiParams.getNotBefore());
    certGen.setNotAfter(uiParams.getNotAfter());
    certGen.setSubjectDN(xp);
    certGen.setPublicKey(pubKey);
    certGen.setSignatureAlgorithm(uiParams.getSignatureAlgorithm());
    
    //adding extensions
    //key ids
    if(uiParams.isExtensionKeyIdentifier()) {
      
      //converting a string into valid format for authorityKeyIdentifier
      List<GeneralName> names = new ArrayList();
      GeneralName altName = new GeneralName(GeneralName.dNSName, uiParams.getCommonName());
      names.add(altName);
      GeneralName [] listToArray = new GeneralName[names.size()];
      names.toArray(listToArray);
      GeneralNames authorityName = new GeneralNames(listToArray);
      
      SubjectKeyIdentifier sKID = new SubjectKeyIdentifier(pubKey.getEncoded());
      AuthorityKeyIdentifier aKID = new AuthorityKeyIdentifier(authorityName, uiParams.getSerialNumber());
      
      //sKID and aKID must not be critical, from documentation
      certGen.addExtension(Extension.subjectKeyIdentifier, false, sKID);
      certGen.addExtension(Extension.authorityKeyIdentifier, false, aKID);
    }
    
    //Alternative names
    if(uiParams.getExtensionsubjectAlternativeName().length > 0) {
      List<GeneralName> names = new ArrayList();
      for(String name: uiParams.getExtensionsubjectAlternativeName()) {
        GeneralName altName = new GeneralName(GeneralName.dNSName, name);
        names.add(altName);
      }
      GeneralName [] listToArray = new GeneralName[names.size()];
      names.toArray(listToArray);
      GeneralNames subjectAltName = new GeneralNames(listToArray);
      certGen.addExtension(Extension.subjectAlternativeName, uiParams.isExtensionSubjectAlternativeNameIsCritical(), subjectAltName); 
    }
    
    
    //Basic constraints
    BasicConstraints basicConstraint;
    if(uiParams.isExtensionIsCertificateAuthority()) {
      Integer pathLen = 0;
      if(uiParams.getExtensionPathLength().compareTo("") != 0) 
        pathLen = Integer.parseInt(uiParams.getExtensionPathLength());
        
      basicConstraint = new BasicConstraints(pathLen);
    } else {
      basicConstraint = new BasicConstraints(false);
    }
    
    certGen.addExtension(X509Extensions.BasicConstraints, uiParams.isExtensionBasicConstraintsIsCritical(), basicConstraint);
    
    
    result = certGen.generateX509Certificate(privKey, "BC");
    return result;
  }
  
  public static X509Certificate signCertificate(KeyStore.PrivateKeyEntry subjectEntry, KeyStore.PrivateKeyEntry issuerEntry) throws Exception {
    X509Certificate result = null;
    X509Certificate subjectCert = (X509Certificate) subjectEntry.getCertificate();
    X509Certificate issuerCert = (X509Certificate) issuerEntry.getCertificate();
    X509CertImpl impl = new X509CertImpl(subjectCert.getEncoded());
    String CN="", OU="", O="", L="", ST="", C="";
    
    Principal subjectDN = subjectCert.getSubjectDN();
    LdapName ln = new LdapName(subjectDN.toString());
    int i = 1; // used for mapping DN attributes to fields
    for(Rdn rdn : ln.getRdns()) {
//        CN=i,OU=i,O=i,L=i,ST=i,C=i
//        i = 1 ... 6
      switch(i) {
        case 6:
          CN = rdn.getValue().toString();
          break;
        case 5:
          OU = rdn.getValue().toString();
          break;
        case 4:
          O = rdn.getValue().toString();
          break;
        case 3:
          L = rdn.getValue().toString();
          break;
        case 2:
          ST = rdn.getValue().toString();
          break;
        case 1:
          C = rdn.getValue().toString();
          break;
      }
      i++;
    }
    //String name, String country, String state, String locality, String organization, String organizationUnit, String commonName, 
    //String signatureAlgorithm, int subjectCertificateVersion, BigInteger serialNumber, Date notBefore, Date notAfter, String keyLength, //String publicKeyAlgorithm, boolean extensionKeyIdentifier, String[] extensionsubjectAlternativeNamextensionSubjectAlternativeNameIsCritical, boolean extensionBasicConstraintsIsCritical, //boolean extensionIsCertificateAuthority
    boolean subjectAndAuthorityExists = false;
    boolean isCriticalAltNames = false, isCriticalBasicConstraints = false;
    
    Collection sANsCollection = impl.getSubjectAlternativeNames();
    String sANs [];
    if(sANsCollection != null) {
      sANs = new String[sANsCollection.size()];
      // each item of collection is a List, where List(0) - Integer that represents the type of alternative name and List(1) - the actual name
      i=0;
      for (Iterator iterator = sANsCollection.iterator(); iterator.hasNext();) {
        List<Object> nameTypePair = (List<Object>) iterator.next();   
        Integer typeOfAlternativeName = (Integer)nameTypePair.get(0);
        String alternativeName = (String) nameTypePair.get(1);
        sANs[i++] = alternativeName;
      }
    } else {
      sANs = new String[0];
    }
    byte sKIDb[] = impl.getExtensionValue(Extension.subjectKeyIdentifier.toString());
    
    //checks if key identifier exists
    if(sKIDb != null) {
      subjectAndAuthorityExists = true;
    }
    
    //checks what's critical
    Set<String> criticals = impl.getCriticalExtensionOIDs();
    for(String item: criticals){
      if(item.compareTo(Extension.subjectAlternativeName.toString()) == 0) {
        isCriticalAltNames = true;
      } else if (item.compareTo(Extension.basicConstraints.toString()) == 0) {
        isCriticalBasicConstraints = true;
      }
    }
    
    //gets the certs basic constraint
    BasicConstraints basicConstraints = null;
    byte[] extVal = impl.getExtensionValue(Extension.basicConstraints.toString());
    
    Object obj = new ASN1InputStream(extVal).readObject();
    extVal = ((DEROctetString) obj).getOctets();
    obj = new ASN1InputStream(extVal).readObject();
    basicConstraints = BasicConstraints.getInstance((ASN1Sequence) obj);
   
    //public UIParameters(String name, String country, String state, String locality, String organization, String organizationUnit, String commonName, String signatureAlgorithm, int subjectCertificateVersion, BigInteger serialNumber, Date notBefore, Date notAfter, String keyLength, String publicKeyAlgorithm, boolean extensionKeyIdentifier, String[] extensionsubjectAlternativeName, String extensionPathLength,boolean extensionKeyIdentifierIsCritical, boolean extensionSubjectAlternativeNameIsCritical, boolean extensionBasicConstraintsIsCritical, boolean extensionIsCertificateAuthority) {
    UIParameters ui = new UIParameters(impl.getName(), C, ST, L, O, OU, CN, impl.getSigAlgName(), impl.getVersion(), impl.getSerialNumber(), impl.getNotBefore(), impl.getNotAfter(), "512", impl.getPublicKey().getAlgorithm(), subjectAndAuthorityExists, sANs, (basicConstraints.isCA())?basicConstraints.getPathLenConstraint().toString():"0", false, isCriticalAltNames, isCriticalBasicConstraints, basicConstraints.isCA());
    
    result = getInstance().generateCertificate(ui, subjectCert.getPublicKey(), issuerEntry.getPrivateKey(), false, issuerCert.getSubjectDN());
    
    return result;
  }

  public static X509Utils getInstance() throws Exception {
    if(instance == null)
      instance = new X509Utils();
    return instance;
  }
  
  public KeyStore getKeyStore() {
    return instance.keyStore;
  }

  public static String getKeyStorePassword() {
    return keyStorePassword;
  }

  public static String getKeyStoreFileName() {
    return keyStoreFileName;
  }
}
