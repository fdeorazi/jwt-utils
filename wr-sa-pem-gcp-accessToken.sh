serviceAccount=iotserver-wr-sa@iot-weather-station-project.iam.gserviceaccount.com
defScope=https://www.googleapis.com/auth/cloud-platform
if [ -n $1 ];then scope=$1; else scope=$defScope;fi
echo scope: $scope
java -jar target/jwt-utils-1.0.0.jar -accessToken \
  -pem $IOTWS_KEYS/pkey-wr.pem \
  $serviceAccount \
  $scope
