# x509
X.509 Authentication Service


#installation notes
#
#add libs to local mvn repository, run this command in project root folders

mvn install:install-file -Dfile=lib/jdatepicker-1.3.4.jar -DgroupId=etf.bg.ac.rs -DartifactId=jdatepicker -Dversion=1.3.4 -Dpackaging=jar -DgeneratePom=true
mvn install:install-file -Dfile=lib/X509_2017.jar -DgroupId=etf.bg.ac.rs -DartifactId=gui -Dversion=1.0 -Dpackaging=jar -DgeneratePom=true

