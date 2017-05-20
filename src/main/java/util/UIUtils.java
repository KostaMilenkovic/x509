package util;

import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import model.UIParameters;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import x509.v3.GuiV3;

public class UIUtils {
  
  public static UIParameters mapUIToModel(GuiV3 access, String string) {
    UIParameters result = null;
    String name = string;
    String subjectCountry = access.getSubjectCountry();
    String subjectState = access.getSubjectState();
    String subjectLocality = access.getSubjectLocality();
    String subjectOrganization = access.getSubjectOrganization();
    String subjectOrganizationUnit = access.getSubjectOrganizationUnit();
    String subjectCommonName = access.getSubjectCommonName();
    String subjectSignatureAlgorithm = access.getPublicKeySignatureAlgorithm();
    int subjectCertificateVersion = access.getVersion();
    BigInteger subjectSerialNumber = new BigInteger(access.getSerialNumber());
    Date notBefore = access.getNotBefore();
    Date notAfter = access.getNotAfter();
    String keyLength = access.getPublicKeyParameter();
    String publicKeyAlgorithm = access.getPublicKeyAlgorithm();
    boolean extensionKeyIdentifier = access.getEnabledKeyIdentifiers();
    String[] extensionsubjectAlternativeName = access.getAlternativeName(5);
    String pathLength = access.getPathLen();
    boolean extensionKeyIdentifierIsCritical = access.isCritical(0);
    boolean extensionSubjectAlternativeNameIsCritical = access.isCritical(5);
    boolean extensionBasicConstraintsIsCritical = access.isCritical(8);
    boolean extensionIsCertificateAuthority = access.isCA();
    
    
    result = new UIParameters(name,subjectCountry,subjectState,subjectLocality,subjectOrganization,subjectOrganizationUnit,subjectCommonName,subjectSignatureAlgorithm, subjectCertificateVersion,subjectSerialNumber,notBefore,notAfter, keyLength, publicKeyAlgorithm, extensionKeyIdentifier,extensionsubjectAlternativeName, pathLength, extensionKeyIdentifierIsCritical, extensionSubjectAlternativeNameIsCritical, extensionBasicConstraintsIsCritical, extensionIsCertificateAuthority);
    
    return result;
  }
  
  public static int mapCertificateToUI(GuiV3 access, X509Certificate cert)  {
    int result = -1;
    try {
      setSubjectFields(access, cert);
      setExtensionFields(access, cert);
      setIssuerFields(access, cert);
      if(cert.getSubjectDN().getName().compareTo(cert.getIssuerDN().getName()) == 0) {
        result = 0;
      } else {
        result = 1;
      }
    } catch (Exception ex) {
      result = -1;
    }
    
    return result;
  }
  
  public static void setSubjectFields(GuiV3 access, X509Certificate cert) throws Exception {
    Principal subjectDN = cert.getSubjectDN();
    LdapName ln = new LdapName(subjectDN.toString());
    int i = 1; // used for mapping DN attributes to fields
    for(Rdn rdn : ln.getRdns()) {
//        CN=i,OU=i,O=i,L=i,ST=i,C=i
//        i = 1 ... 6
      switch(i) {
        case 6:
          access.setSubjectCommonName(rdn.getValue().toString());
          break;
        case 5:
          access.setSubjectOrganizationUnit(rdn.getValue().toString());
          break;
        case 4:
          access.setSubjectOrganization(rdn.getValue().toString());
          break;
        case 3:
          access.setSubjectLocality(rdn.getValue().toString());
          break;
        case 2:
          access.setSubjectState(rdn.getValue().toString());
          break;
        case 1:
          access.setSubjectCountry(rdn.getValue().toString());
          break;
      }
      i++;
    }
    
    access.setVersion((cert.getVersion())==3?2:1);
    access.setSerialNumber(cert.getSerialNumber().toString());
    access.setNotBefore(cert.getNotBefore());
    access.setNotAfter(cert.getNotAfter());
  }
  
  public static void setExtensionFields(GuiV3 access, X509Certificate cert) throws Exception {
    //key identifier fields
    SubjectKeyIdentifier sKID = new SubjectKeyIdentifier(cert.getExtensionValue(Extension.subjectKeyIdentifier.toString()));
    AuthorityKeyIdentifier aKID = new AuthorityKeyIdentifier(cert.getExtensionValue(Extension.authorityKeyIdentifier.toString()));
    
    //key identifier fields
    if((aKID.getKeyIdentifier() != null) && (sKID.getKeyIdentifier() != null )) {
      Principal issuerDN = cert.getIssuerDN();
      LdapName ln2 = new LdapName(issuerDN.toString());
      
      access.setAuthorityKeyID(aKID.getKeyIdentifier().toString());
      access.setSubjectKeyID(sKID.getKeyIdentifier().toString());
      access.setAuthorityIssuer(ln2.getRdn(1).getValue().toString());
      access.setAuthoritySerialNumber(cert.getSerialNumber().toString());
      access.setEnabledKeyIdentifiers(true);
    } else {
      access.setEnabledKeyIdentifiers(false);
    }
    
    //alternative name fields
    Collection sANs = cert.getSubjectAlternativeNames();
    
    if(sANs != null) {
//      access.setCritical(5, );
      
      // each item of collection is a List, where List(0) - Integer that represents the type of alternative name and List(1) - the actual name
      String sANField = "";
      int i = 0;
      for (Iterator iterator = sANs.iterator(); iterator.hasNext();) {
        List<Object> nameTypePair = (List<Object>) iterator.next();   
        Integer typeOfAlternativeName = (Integer)nameTypePair.get(0);
        String alternativeName = (String) nameTypePair.get(1);
        sANField += alternativeName;
        if(i<sANs.size()-1) 
          sANField += ",";
        i++;
      }
      access.setAlternativeName(5, sANField);
    }
    
    //basic constraint fields

    byte[] extVal = cert.getExtensionValue(Extension.basicConstraints.toString());
    if (extVal != null) {
      Object obj = new ASN1InputStream(extVal).readObject();
      extVal = ((DEROctetString) obj).getOctets();
      obj = new ASN1InputStream(extVal).readObject();
      BasicConstraints basicConstraints = BasicConstraints.getInstance((ASN1Sequence) obj);
      access.setCA(basicConstraints.isCA());
      if(basicConstraints.isCA()) {
        access.setPathLen(basicConstraints.getPathLenConstraint().toString());
      }
    }
    
    
    //setting critical fields 0- key ids, 5-alt names, 8-basicConstraints
    Set<String> criticals = cert.getCriticalExtensionOIDs();
    
    criticals.forEach((criticalElement) -> {
      if(criticalElement.compareTo(Extension.subjectAlternativeName.toString()) == 0) {
        access.setCritical(5, true);
      } else if (criticalElement.compareTo(Extension.basicConstraints.toString()) == 0) {
        access.setCritical(8, true);
      }
    });
    access.setCritical(0, false);
  }
  
  public static void setIssuerFields(GuiV3 access, X509Certificate cert) throws Exception {
    Principal issuerDN = cert.getIssuerDN();
    String issuerString = issuerDN.toString().replace(" ", "");
  
    access.setIssuer(issuerString);
    access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
  }
}
