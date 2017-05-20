package model;

import java.math.BigInteger;
import java.util.Date;

public class UIParameters {
  private String name;
  private String country;
  private String state;
  private String locality;
  private String organization;
  private String organizationUnit;
  private String commonName;
  private String signatureAlgorithm;
  private int certificateVersion;
  private BigInteger serialNumber;
  private Date notBefore;
  private Date notAfter;
  private String keyLength;
  private String publicKeyAlgorithm;
  private boolean extensionKeyIdentifier;
  private String[] extensionsubjectAlternativeName;
  private String extensionPathLength;
  private boolean extensionKeyIdentifierIsCritical;
  private boolean extensionSubjectAlternativeNameIsCritical;
  private boolean extensionBasicConstraintsIsCritical;
  private boolean extensionIsCertificateAuthority;
  
  public String toString() {
    String res = "";
    int len = 0;
    res += "Name: "+name
            +"\nCountry: "+country
            +"\nState: "+state
            +"\nLocality: "+locality
            +"\nOrganization: "+organization
            +"\nOrg Unit: "+organizationUnit
            +"\nCommon Name: "+commonName
            +"\nSign Alg: "+signatureAlgorithm
            +"\nCert Vers: "+certificateVersion
            +"\nSer Number: "+serialNumber
            +"\nNot Before: "+notBefore
            +"\nNot After: "+notAfter
            +"\nKey Length: "+keyLength
            +"\nPub key alg: "+publicKeyAlgorithm
            +"\nExt Key Id: "+extensionKeyIdentifier
            +"\nExt sub alt name: ";
    
    for(String item: extensionsubjectAlternativeName) {
      res+=item;
      
      len++;
      if(len != extensionsubjectAlternativeName.length)
        res+=',';
    }
    
    res+="\nExt Key path length: "+extensionPathLength
       +"\nExt Key Id is crit: "+extensionKeyIdentifierIsCritical
       +"\nExt sub alt name is crit:"+extensionSubjectAlternativeNameIsCritical
       +"\nExt basic const is crit: "+extensionBasicConstraintsIsCritical
       +"\nExt is cert auth: "+extensionIsCertificateAuthority;
//       +"\nPublic key: "+ keyPair.getPublic().toString()
//       +"\nPrivate key: "+ keyPair.getPrivate().toString();
    
    return res;
  }
  
  public String getDn() {
    String res = "";
    res += "C="+getCountry()+",ST="+getState()+",L="+getLocality()+",O="+getOrganization()+",OU="+getOrganizationUnit()+",CN="+getCommonName();
    return res;
  }
  
  public UIParameters(String name, String country, String state, String locality, String organization, String organizationUnit, String commonName, String signatureAlgorithm, int subjectCertificateVersion, BigInteger serialNumber, Date notBefore, Date notAfter, String keyLength, String publicKeyAlgorithm, boolean extensionKeyIdentifier, String[] extensionsubjectAlternativeName, String extensionPathLength,boolean extensionKeyIdentifierIsCritical, boolean extensionSubjectAlternativeNameIsCritical, boolean extensionBasicConstraintsIsCritical, boolean extensionIsCertificateAuthority) {
    this.name = name;
    this.country = country;
    this.state = state;
    this.locality = locality;
    this.organization = organization;
    this.organizationUnit = organizationUnit;
    this.commonName = commonName;
    this.signatureAlgorithm = signatureAlgorithm;
    this.certificateVersion = subjectCertificateVersion;
    this.serialNumber = serialNumber;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.keyLength = keyLength;
    this.publicKeyAlgorithm = publicKeyAlgorithm;
    this.extensionKeyIdentifier = extensionKeyIdentifier;
    this.extensionsubjectAlternativeName = extensionsubjectAlternativeName;
    this.extensionKeyIdentifierIsCritical = extensionKeyIdentifierIsCritical;
    this.extensionPathLength = extensionPathLength;
    this.extensionSubjectAlternativeNameIsCritical = extensionSubjectAlternativeNameIsCritical;
    this.extensionBasicConstraintsIsCritical = extensionBasicConstraintsIsCritical;
    this.extensionIsCertificateAuthority = extensionIsCertificateAuthority;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    this.country = country;
  }

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public String getLocality() {
    return locality;
  }

  public void setLocality(String locality) {
    this.locality = locality;
  }

  public String getOrganization() {
    return organization;
  }

  public void setOrganization(String organization) {
    this.organization = organization;
  }

  public String getOrganizationUnit() {
    return organizationUnit;
  }

  public void setOrganizationUnit(String organizationUnit) {
    this.organizationUnit = organizationUnit;
  }

  public String getCommonName() {
    return commonName;
  }

  public void setCommonName(String commonName) {
    this.commonName = commonName;
  }

  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  public void setSignatureAlgorithm(String signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  public int getCertificateVersion() {
    return certificateVersion;
  }

  public void setCertificateVersion(int certificateVersion) {
    this.certificateVersion = certificateVersion;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(BigInteger serialNumber) {
    this.serialNumber = serialNumber;
  }

  public Date getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(Date notBefore) {
    this.notBefore = notBefore;
  }

  public Date getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(Date notAfter) {
    this.notAfter = notAfter;
  }

  public String getKeyLength() {
    return keyLength;
  }

  public void setKeyLength(String keyLength) {
    this.keyLength = keyLength;
  }

  public String getPublicKeyAlgorithm() {
    return publicKeyAlgorithm;
  }

  public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
    this.publicKeyAlgorithm = publicKeyAlgorithm;
  }

  public boolean isExtensionKeyIdentifier() {
    return extensionKeyIdentifier;
  }

  public void setExtensionKeyIdentifier(boolean extensionKeyIdentifier) {
    this.extensionKeyIdentifier = extensionKeyIdentifier;
  }

  public String[] getExtensionsubjectAlternativeName() {
    return extensionsubjectAlternativeName;
  }

  public void setExtensionsubjectAlternativeName(String[] extensionsubjectAlternativeName) {
    this.extensionsubjectAlternativeName = extensionsubjectAlternativeName;
  }

  public boolean isExtensionKeyIdentifierIsCritical() {
    return extensionKeyIdentifierIsCritical;
  }

  public void setExtensionKeyIdentifierIsCritical(boolean extensionKeyIdentifierIsCritical) {
    this.extensionKeyIdentifierIsCritical = extensionKeyIdentifierIsCritical;
  }

  public boolean isExtensionSubjectAlternativeNameIsCritical() {
    return extensionSubjectAlternativeNameIsCritical;
  }

  public void setExtensionSubjectAlternativeNameIsCritical(boolean extensionSubjectAlternativeNameIsCritical) {
    this.extensionSubjectAlternativeNameIsCritical = extensionSubjectAlternativeNameIsCritical;
  }

  public boolean isExtensionBasicConstraintsIsCritical() {
    return extensionBasicConstraintsIsCritical;
  }

  public void setExtensionBasicConstraintsIsCritical(boolean extensionBasicConstraintsIsCritical) {
    this.extensionBasicConstraintsIsCritical = extensionBasicConstraintsIsCritical;
  }

  public boolean isExtensionIsCertificateAuthority() {
    return extensionIsCertificateAuthority;
  }

  public void setExtensionIsCertificateAuthority(boolean extensionIsCertificateAuthority) {
    this.extensionIsCertificateAuthority = extensionIsCertificateAuthority;
  }

  public String getExtensionPathLength() {
    return extensionPathLength;
  }

  public void setExtensionPathLength(String extensionPathLength) {
    this.extensionPathLength = extensionPathLength;
  }
}
