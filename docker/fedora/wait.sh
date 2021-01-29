#!/bin/sh
# wait.sh

set -e
  
file="$1"
shift
cmd="$@"
  
# while ! nc -z $host 8881;
while ! test -f $file;
do
  >&2 echo "Verifier certificate unavailable - sleeping"
  sleep 2
done

>&2 echo "Verifier certificate available - executing registrar"
exec $cmd