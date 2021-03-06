![GitHub Light](https://i.ytimg.com/vi/QO96zU4cZSc/maxresdefault.jpg)


# HIVE-INDICADORES-DE-COMPROMISO-IOCs

Indicadores de compromiso del grupo cibercriminal HIVE, relacionado al reciente ataque de la C.C.S.S de Costa Rica 馃嚚馃嚪. 

El  31 de Mayo del 2022, en horas de la madrugada se registro un posible ciberataque a los sistemas de la caja costarricense del seguro social C.C.S.S de tipo ransomware y exfiltracion de datos, en respuesta al cieberataque se creo este documento para que las empresas y organizaciones del pais puedan implementar de manera temprana protecciones contra las tecnicas y dispositivos utilizados por el grupo cibercriminal HIVE.



# Herramientas y tecnicas utilizadas

[ProxyShell:](https://www.cronup.com/proxyshell-el-nuevo-rce-en-microsoft-exchange-version-latam/)  es el nombre que se le ha dado a la ejecuci贸n de tres vulnerabilidades en la plataforma Microsoft Exchange, que al ser encadenadas, permiten la ejecuci贸n de c贸digo remoto no autenticado en el servidor.
Las versiones vulnerables son:

- Microsoft Exchange Server 2019.
- Microsoft Exchange Server 2016.
- Microsoft Exchange Server 2013.

Guia para parchear servidores de exchange [aqui](https://techcommunity.microsoft.com/t5/exchange-team-blog/proxyshell-vulnerabilities-and-your-exchange-server/ba-p/2684705)

[Cobalt Strike](https://www.cobaltstrike.com/) La herramienta de RedTeam Cobalt Strike es muy utilizado por los diferentes actores de amenazas (com煤nmente por afiliados de bandas de ransomwares) para las tareas de post-explotaci贸n y despu茅s desplegar los llamados beacons, que proporcionan acceso remoto persistente a los dispositivos comprometidos.

[Mimikatz](https://github.com/ParrotSec/mimikatz)  es una aplicaci贸n de c贸digo abierto que permite a los usuarios ver y guardar credenciales de autenticaci贸n, como tickets de Kerberos

# Vulnerabilidades mas comunes explotadas

[]()
[CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473) (puntuaci贸n base: 9,8)
Vulnerabilidad de ejecuci贸n remota de c贸digo de Microsoft Exchange Server.

[CVE-2021-34523](https://nvd.nist.gov/vuln/detail/CVE-2021-34523) (puntuaci贸n base: 9,8)
Vulnerabilidad de elevaci贸n de privilegios de Microsoft Exchange Server

[CVE-2021-31207](https://www.cvedetails.com/cve/CVE-2021-31207/) (puntuaci贸n base: 7,2)
Vulnerabilidad de omisi贸n de la caracter铆stica de seguridad de Microsoft Exchange Server

Microsoft lanz贸 parches para esas tres vulnerabilidades en abril y mayo de 2021 como parte de sus lanzamientos de "Patch Tuesday". CVE-2021-34473 y CVE-2021-34523 se parchearon [KB5001779](https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-april-13-2021-kb5001779-8e08f3b3-fc7b-466c-bbb7-5d5aa16ef064) en abril de 2021. CVE-2021-31207 se parche贸 [KB5003435](https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-may-11-2021-kb5003435-028bd051-b2f1-4310-8f35-c41c9ce5a2f1) en mayo.


# OnionLinks


- http://hiveleakdbtnp76ulyhi52eag6c6tyc3xw7ez7iqy6wc34gd2nekazyd.onion/
-  http://hivecust6vhekztbqgdnkks64ucehqacge3dij3gyrrpdp57zoq3ooqd.onion 
-  
# Direcciones IP

- 139.60.161.228
- 139.60.161.56
- 91.208.52.149
- 185.70.184.8
- 9.60.161.228 
- 139.60.161.56 
- 91.208.52.149 
- 185.70.184.8 
- 139.60.161.24 
- 139.60.161.236 
- 139.60.161.216 
- 139.60.161.213 
- 139.60.161.75 
- 139.60.161.52 
- 139.60.161.85 
- 139.60.161.43 
- 139.60.161.209 
- 139.60.161.215 
- 139.60.161.47 
- 139.60.161.45 
- 139.60.161.208 
- 139.60.161.84 
- 139.60.161.99 
- 185.70.184.41 
- 84.32.188.189 
- 84.32.188.104 
- 84.32.188.93 
- 84.32.188.197 
-  84.32.188.190 
-  84.32.188.60
-  84.32.188.202
-  84.32.188.250 
-  84.32.188.40 
-  84.32.188.1
-  84.32.188.237
-  84.32.188.65 
-  84.32.188.29 
-  175.178.62.140 
-  175.178.62.100 
-  1.15.80.102 
-  47.242.86.193 
-  47.242.86.193 
-  47.242.86.26 
-  176.123.8.228 
-  46.166.161.123 
-  46.166.161.93 
-  192.53.123.202 
-  159.223.143.85
-  172.99.69.6 
-  198.211.125.198 
-  103.146.179.89 
-  1.15.80.102 
-  175.178.62.140 
-  84.32.188.238 
-  5.199.173.96 
-  93.115.29.50 
-  104.253.201.106 
-  139.60.161.228 
-  139.60.161.56 
-  185.70.184.8 
-  91.208.52.149





# Procesos Maliciosos

| Proceso | MD5 | SHA1 |
| --- | --- | --- |
| Mimikatz.exe | 6c9ad4e67032301a61a9897377d9cff8 |655979d56e874fbe7561bb1b6e512316c25cbb19 |
| H-Tool Mimikatz | - | E81A8F8AD804C4D83869D7806A303FF04F31CCE376C5DF8AADA2E9DB2C1EEB98 |
| advanced_port_scanner_2.5.3869.exe| 6a58b52b184715583cda792b56a0a1ed | 3477a173e2c1005a81d042802ab0f22cc12a4d55 |
| advanced port scanner.exe | 4fdabe571b66ceec3448939bfb3ffcd1 | 763499b37aacd317e7d2f512872f9ed719aacae1 |
| scan.exe | bb7c575e798ff5243b5014777253635d | 2146f04728fe93c393a74331b76799ea8fe0269f |
| p.bat	| 5e1575c221f8826ce55ac2696cf1cf0b | ecf794599c5a813f31f0468aecd5662c5029b5c4 |
| Webshell #1| d46104947d8478030e8bcfcc74f2aef7 | d1ef9f484f10d12345c41d6b9fca8ee0efa29b60 |
| Webshell #2 | 2401f681b4722965f82a3d8199a134ed | 2aee699780f06857bb0fb9c0f73e33d1ac87a385 |
| winlo | b5045d802394f4560280a7404af69263 | 321d0c4f1bbb44c53cd02186107a18b7a44c840a9a5f0a78bdac06868136b72c |
| 7zG.exe | 04FB3AE7F05C8BC333125972BA907398 | - |
| Winlo_dump_64_SCY.exe | BEE9BA70F36FF250B31A6FDF7FA8AFEB | - |



# Hashes

## MD5 

* b5045d802394f4560280a7404af69263
* 04fb3ae7f05c8bc333125972ba907398
* abeja9ba70f36ff250b31a6fdf7fa8afeb
* eda8d43b2912eba1eb9379b66aa782cc
* 6c9ad4e67032301a61a9897377d9cff8
* 6a58b52b184715583cda792b56a0a1ed
* 4fdabe571b66ceec3448939bfb3ffcd1
* bb7c575e798ff5243b5014777253635d
* 5e1575c221f8826ce55ac2696cf1cf0b
* d46104947d8478030e8bcfcc74f2aef7
* 2401f681b4722965f82a3d8199a134ed

## SHA1

* f1a8eedd429446b93574105e205bd12d980a0040
* 655979d56e874fbe7561bb1b6e512316c25cbb19
* 477a173e2c1005a81d042802ab0f22cc12a4d55
* 763499b37aacd317e7d2f512872f9ed719aacae1
* 2146f04728fe93c393a74331b76799ea8fe0269f
* ecf794599c5a813f31f0468aecd5662c5029b5c4
* d1ef9f484f10d12345c41d6b9fca8ee0efa29b60
* 2aee699780f06857bb0fb9c0f73e33d1ac87a385

## SHA256 

* 321d0c4f1bbb44c53cd02186107a18b7a44c840a9a5f0a78bdac06868136b72c
* 2e52494e776be6433c89d5853f02b536f7da56e94bbe86ae4cc782f85cama2c4b
* E81A8F8AD804C4D83869D7806A303FF04F31CCE376C5DF8AADA2E9DB2C1EEB98

# Nombres de archivos 

* *.key.hive
*.key.*
* HOW_TO_DECRYPT.txt
* hive.bat
* shadow.bat
* vssadmin.exe delete shadows /all /quiet
* wmic.exe SHADOWCOPY /nointeractive
* wmic.exe shadowcopy delete
* wevtutil.exe cl system
* wevtutil.exe cl security
* wevtutil.exe cl application
* bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
* bcdedit.exe /set {default} recoveryenabled no


# Dominios

- hXXp://hiveleakdbtnp76ulyhi52eag6c6tyc3xw7ez7iqy6wc34gd2nekazyd[.]onion
- hXXp://hivecust6vhekztbqgdnkks64ucehqacge3dij3gyrrpdp57zoq3ooqd[.]onion
- hXXp://ciscosecuritu[.]com/components/html[.]gif
- hXXp://198[.]211[.]125[.]198:24001/
- nzwindowshades[.]co[.]nz
- rmqn[.]stripreflow[.]io
- sawley-inf[.]derbyshire[.]sch[.]uk
- controller@nzwindowshades[.]co[.]nz
- hXXp://159[.]223.[.]143[.]85
- hXXp://159[.]223[.]143[.]85/fdkjghdfjkgvutereryecfc/kdfjhgskdjgheterererwfkcbswcfe/dsfkjdgsttrrererwbdk776653ncfkbvge[.]php
- hXXp://www[.]epoolsoft[.]com/PCHunter_StandardV1.55=658897218D38F45E324FC79A562BC8CB2716FCBD73AF103E0E4A6DA0EABDC16784F00B1FB150637D23467C825D80B92A
- hXXp://clscovpn[.]com/ny[.]html

# Recomendaciones 

* Actualice el servidor de Exchange a la actualizaci贸n acumulativa (CU) y la actualizaci贸n de seguridad (SU) de Exchange m谩s recientes proporcionadas por Microsoft.
* Exija el uso de contrase帽as complejas y solicite a los usuarios que cambien las contrase帽as peri贸dicamente.
* Todas las cuentas basadas en contrase帽a (como las cuentas de servicio, administrador y administrador de dominio) deben tener contrase帽as seguras y 煤nicas.
* Implemente la autenticaci贸n multifactor para todos los servicios en la medida de lo posible, especialmente para correo web, redes privadas virtuales VPN y cuentas que acceden a sistemas cr铆ticos.
* Utilice la soluci贸n [LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899) de Microsoft para revocar los permisos de administrador local de las cuentas de dominio (el principio de privilegio m铆nimo) y verifique y elimine peri贸dicamente las cuentas de usuario inactivas.
* [Bloquee](https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858) el uso de SMBv1 y use la firma de SMB para protegerse contra el ataque pass-the-hash.
* Restrinja el acceso al m铆nimo requerido para los roles en su organizacion.
* Mantenga copias de seguridad de datos fuera de l铆nea y realice copias de seguridad y restauraciones peri贸dicas. Esta pr谩ctica asegura que no habr谩 cortes importantes en la organizaci贸n, ni datos irrecuperables en caso de un ataque de ransomware.
* Aseg煤rese de que todos los datos de copia de seguridad est茅n encriptados, sean inmutables (es decir, no se puedan cambiar ni eliminar) y abarquen toda la infraestructura de datos de la organizaci贸n.
* Deshabilite las conexiones de escritorio remoto, use las cuentas con menos privilegios. Restrinja a los usuarios que pueden iniciar sesi贸n usando Escritorio remoto, establezca una pol铆tica de bloqueo de cuenta. Aseg煤rese de que el registro y la configuraci贸n de RDP sean adecuados
* Instale Autenticaci贸n, informes y cumplimiento de mensajes basados en dominios (DMARC), Correo identificado con claves de dominio (DKIM) y Marco de pol铆ticas del remitente (SPF) para su dominio, que es un sistema de inspecci贸n de correo electr贸nico dise帽ado para evitar el correo no deseado al detectar [Mas informacion aqui](https://www.simla.com/blog/spf-dkim-y-dmarc#:~:text=SPF%2C%20DKIM%20y%20DMARC%20son,protocolos%20son%20f%C3%A1ciles%20de%20configurar.)
* Mantenga su software antivirus actualizado en todos los sistemas. Utilize una solucion tipo [EDR](https://www.incibe.es/protege-tu-empresa/blog/sistemas-edr-son-y-ayudan-proteger-seguridad-tu-empresa) Endpoint Detection and response en activos criticos tales como servidores. 
* Segmentaci贸n de la red y divisi贸n en zonas de seguridad: ayude a proteger la informaci贸n confidencial y los servicios cr铆ticos. Separe la red administrativa de los procesos comerciales con controles f铆sicos y VLAN.
* Ejecute una evaluaciones de vulnerabilidades y pruebas de penetraci贸n (VAPT) o auditor铆as de seguridad de la informaci贸n de redes/sistemas cr铆ticos, especialmente servidores de bases de datosaal menos una vez al a帽o.
* Se recomienda a las personas u organizaciones que no paguen el rescate, ya que esto no garantiza que los archivos se liberar谩n.
Reporte tales incidentes al [CSIRT](csirt@micitt.go.cr) y a la polic铆a local.

# Fuentes
- [Hive Ransomware Analysis](https://www.varonis.com/blog/hive-ransomware-analysis)
- [MITRE HIVE](https://attack.mitre.org/groups/G0092/)
- [Indicators of Compromise Associated with Hive Ransomware](https://www.ic3.gov/Media/News/2021/210825.pdf)

# Investigaciones

- [DisCONTInued: The End of Conti鈥檚 Brand Marks New Chapter For Cybercrime Landscape](https://www.advintel.io/post/discontinued-the-end-of-conti-s-brand-marks-new-chapter-for-cybercrime-landscape)
- [Costa Rica鈥檚 public health agency hit by Hive ransomware](https://www.bleepingcomputer.com/news/security/costa-rica-s-public-health-agency-hit-by-hive-ransomware/)
- [Costa Rica May Be Pawn in Conti Ransomware Group鈥檚 Bid to Rebrand, Evade Sanctions](https://krebsonsecurity.com/2022/05/costa-rica-may-be-pawn-in-conti-ransomware-groups-bid-to-rebrand-evade-sanctions/)


# Media Posts
- [Costa Rica鈥檚 public health agency hit by Hive ransomware](https://www.bleepingcomputer.com/news/security/costa-rica-s-public-health-agency-hit-by-hive-ransomware/)
- [CCSS habr铆a sido 鈥榟ackeada鈥? por un brazo de Conti llamado Hive](https://www.nacion.com/el-pais/salud/ccss-habria-sido-atacada-por-un-brazo-de-conti/63LQ5EQXGJF2TNIQP3A6SKTMCQ/story/)
- [Ciberataque al Gobierno de Costa Rica](https://es.wikipedia.org/wiki/Ciberataque_al_Gobierno_de_Costa_Rica)


# Preguntas o colaboraciones

- [hackingmess@protonmail.com](mailto:hackingmess@protonmail.com?subject=HIVE-INDICADORES-DE-COMPROMISO-IOCs)
- [randy@atticyber.com](mailto:randy@atticyber.com?subject=HIVE-INDICADORES-DE-COMPROMISO-IOCs)
- [Linkedin](https://www.linkedin.com/in/rvarelac/)
