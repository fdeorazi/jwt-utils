
set DEBUG=
@rem set DEBUG=-agentlib:jdwp=transport=dt_socket,address=8000,server=y,suspend=y

%java_11_home%\bin\java %DEBUG% -jar target/jwt-utils-1.0.0.jar access-token ^
	-kf pkey-wr.pem ^
	-sa iotserver-wr-sa@iot-weather-station-project.iam.gserviceaccount.com ^
	-ts https://iotserver-wr-jbywjzjd6a-oc.a.run.app ^
	