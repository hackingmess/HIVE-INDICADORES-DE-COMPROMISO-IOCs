![GitHub Light](https://i.ytimg.com/vi/QO96zU4cZSc/maxresdefault.jpg)


# HIVE-INDICADORES-DE-COMPROMISO-IOCs

Indicadores de compromiso del grupo cibercriminal HIVE, relacionado al reciente ataque de la C.C.S.S de Costa Rica 🇨🇷. 

El  31 de Mayo del 2022, en horas de la madrugada se registro un posible ciberataque a los sistemas de la caja costarricense del seguro social C.C.S.S de tipo ransomware y exfiltracion de datos, en respuesta al cieberataque se creo este documento para que las empresas y organizaciones del pais puedan implementar de manera temprana protecciones contra las tecnicas y dispositivos utilizados por el grupo cibercriminal HIVE.



# Herramientas y tecnicas utilizadas

[ProxyShell:](https://www.cronup.com/proxyshell-el-nuevo-rce-en-microsoft-exchange-version-latam/)  es el nombre que se le ha dado a la ejecución de tres vulnerabilidades en la plataforma Microsoft Exchange, que al ser encadenadas, permiten la ejecución de código remoto no autenticado en el servidor.
Las versiones vulnerables son:

- Microsoft Exchange Server 2019.
- Microsoft Exchange Server 2016.
- Microsoft Exchange Server 2013.

Guia para parchear servidores de exchange [aqui](https://techcommunity.microsoft.com/t5/exchange-team-blog/proxyshell-vulnerabilities-and-your-exchange-server/ba-p/2684705)

[Cobalt Strike](https://www.cobaltstrike.com/) La herramienta de RedTeam Cobalt Strike es muy utilizado por los diferentes actores de amenazas (comúnmente por afiliados de bandas de ransomwares) para las tareas de post-explotación y después desplegar los llamados beacons, que proporcionan acceso remoto persistente a los dispositivos comprometidos.

[Mimikatz](https://github.com/ParrotSec/mimikatz)  es una aplicación de código abierto que permite a los usuarios ver y guardar credenciales de autenticación, como tickets de Kerberos

# Vulnerabilidades mas comunes explotadas

[]()
[CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473) (puntuación base: 9,8)
Vulnerabilidad de ejecución remota de código de Microsoft Exchange Server.

[CVE-2021-34523](https://nvd.nist.gov/vuln/detail/CVE-2021-34523) (puntuación base: 9,8)
Vulnerabilidad de elevación de privilegios de Microsoft Exchange Server

[CVE-2021-31207](https://www.cvedetails.com/cve/CVE-2021-31207/) (puntuación base: 7,2)
Vulnerabilidad de omisión de la característica de seguridad de Microsoft Exchange Server

Microsoft lanzó parches para esas tres vulnerabilidades en abril y mayo de 2021 como parte de sus lanzamientos de "Patch Tuesday". CVE-2021-34473 y CVE-2021-34523 se parchearon [KB5001779](https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-april-13-2021-kb5001779-8e08f3b3-fc7b-466c-bbb7-5d5aa16ef064) en abril de 2021. CVE-2021-31207 se parcheó [KB5003435](https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-may-11-2021-kb5003435-028bd051-b2f1-4310-8f35-c41c9ce5a2f1) en mayo.

# Direcciones IP

- 139.60.161.228
- 139.60.161.56
- 91.208.52.149
- 185.70.184.8


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
* .llave.*
* HOW_TO_DECRYPT.txt
* hive.bat
* shadow.bat
* vssadmin.exe 
* wmic.exe SHADOWCOPY 
* sistema cl
* wevtutil.exe 
* wevtutil.exe 
* bcdedit.exe /set 
* bcdedit.exe /set 

# Recomendaciones 

* Actualice el servidor de Exchange a la actualización acumulativa (CU) y la actualización de seguridad (SU) de Exchange más recientes proporcionadas por Microsoft.
* Exija el uso de contraseñas complejas y solicite a los usuarios que cambien las contraseñas periódicamente.
* Todas las cuentas basadas en contraseña (como las cuentas de servicio, administrador y administrador de dominio) deben tener contraseñas seguras y únicas.
* Implemente la autenticación multifactor para todos los servicios en la medida de lo posible, especialmente para correo web, redes privadas virtuales VPN y cuentas que acceden a sistemas críticos.
* Utilice la solución [LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899) de Microsoft para revocar los permisos de administrador local de las cuentas de dominio (el principio de privilegio mínimo) y verifique y elimine periódicamente las cuentas de usuario inactivas.
* [Bloquee](https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858) el uso de SMBv1 y use la firma de SMB para protegerse contra el ataque pass-the-hash.
* Restrinja el acceso al mínimo requerido para los roles en su organizacion.
* Mantenga copias de seguridad de datos fuera de línea y realice copias de seguridad y restauraciones periódicas. Esta práctica asegura que no habrá cortes importantes en la organización, ni datos irrecuperables en caso de un ataque de ransomware.
* Asegúrese de que todos los datos de copia de seguridad estén encriptados, sean inmutables (es decir, no se puedan cambiar ni eliminar) y abarquen toda la infraestructura de datos de la organización.
* Deshabilite las conexiones de escritorio remoto, use las cuentas con menos privilegios. Restrinja a los usuarios que pueden iniciar sesión usando Escritorio remoto, establezca una política de bloqueo de cuenta. Asegúrese de que el registro y la configuración de RDP sean adecuados
* Instale Autenticación, informes y cumplimiento de mensajes basados en dominios (DMARC), Correo identificado con claves de dominio (DKIM) y Marco de políticas del remitente (SPF) para su dominio, que es un sistema de inspección de correo electrónico diseñado para evitar el correo no deseado al detectar [Mas informacion aqui](https://www.simla.com/blog/spf-dkim-y-dmarc#:~:text=SPF%2C%20DKIM%20y%20DMARC%20son,protocolos%20son%20f%C3%A1ciles%20de%20configurar.)
* Mantenga su software antivirus actualizado en todos los sistemas. Utilize una solucion tipo [EDR](https://www.incibe.es/protege-tu-empresa/blog/sistemas-edr-son-y-ayudan-proteger-seguridad-tu-empresa) Endpoint Detection and response en activos criticos tales como servidores. 
* Segmentación de la red y división en zonas de seguridad: ayude a proteger la información confidencial y los servicios críticos. Separe la red administrativa de los procesos comerciales con controles físicos y VLAN.
* Ejecute una evaluaciones de vulnerabilidades y pruebas de penetración (VAPT) o auditorías de seguridad de la información de redes/sistemas críticos, especialmente servidores de bases de datosaal menos una vez al año.
* Se recomienda a las personas u organizaciones que no paguen el rescate, ya que esto no garantiza que los archivos se liberarán.
Reporte tales incidentes al [CSIRT](csirt@micitt.go.cr) y a la policía local.

# Fuentes
- [Hive Ransomware Analysis](https://www.varonis.com/blog/hive-ransomware-analysis)
- [MITRE HIVE](https://attack.mitre.org/groups/G0092/)

# Investigaciones

- [DisCONTInued: The End of Conti’s Brand Marks New Chapter For Cybercrime Landscape](https://www.advintel.io/post/discontinued-the-end-of-conti-s-brand-marks-new-chapter-for-cybercrime-landscape)
- [Costa Rica’s public health agency hit by Hive ransomware](https://www.bleepingcomputer.com/news/security/costa-rica-s-public-health-agency-hit-by-hive-ransomware/)
- [Costa Rica May Be Pawn in Conti Ransomware Group’s Bid to Rebrand, Evade Sanctions](https://krebsonsecurity.com/2022/05/costa-rica-may-be-pawn-in-conti-ransomware-groups-bid-to-rebrand-evade-sanctions/)


# Media Posts
- [Costa Rica’s public health agency hit by Hive ransomware](https://www.bleepingcomputer.com/news/security/costa-rica-s-public-health-agency-hit-by-hive-ransomware/)
- [CCSS habría sido ‘hackeada’ por un brazo de Conti llamado Hive](https://www.nacion.com/el-pais/salud/ccss-habria-sido-atacada-por-un-brazo-de-conti/63LQ5EQXGJF2TNIQP3A6SKTMCQ/story/)
- [Ciberataque al Gobierno de Costa Rica](https://es.wikipedia.org/wiki/Ciberataque_al_Gobierno_de_Costa_Rica)


# Preguntas o colaboraciones

- [hackingmess@protonmail.com](mailto:hackingmess@protonmail.com?subject=HIVE-INDICADORES-DE-COMPROMISO-IOCs)
- [randy@atticyber.com](mailto:randy@atticyber.com?subject=HIVE-INDICADORES-DE-COMPROMISO-IOCs)
- [Linkedin](https://www.linkedin.com/in/rvarelac/)
