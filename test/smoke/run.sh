#!/bin/sh
# Runs IMAGE the way users do and checks it works: the container must pass its
# own health check, run as the unprivileged user, and serve signed requests:
# send a message through the SES API and read it back through the retrieval
# API, kept in the store on its volume.
set -eu

image=${1:?usage: run.sh IMAGE}
name=mailbox-smoke-$$

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker logs "$name" || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

docker run -d --name "$name" -p 127.0.0.1::9040 \
	-e TULE_Auth_AccessKeyID=smoke -e TULE_Auth_SecretAccessKey=smoke \
	"$image" >/dev/null

# The health check first runs one interval (10s) after start.
health=
for _ in $(seq 60); do
	health=$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$name")
	case $health in
	"running healthy") break ;;
	running*) sleep 1 ;;
	*) echo "container stopped: $health" >&2; exit 1 ;;
	esac
done
if [ "$health" != "running healthy" ]; then
	echo "container never became healthy: $health" >&2
	exit 1
fi

# The image must not run as root: it holds the store in its volume.
ids=$(docker exec "$name" id -u):$(docker exec "$name" id -g)
if [ "$ids" != 65532:65532 ]; then
	echo "runs as $ids, want 65532:65532" >&2
	exit 1
fi

addr=$(docker port "$name" 9040/tcp | head -n 1)

# Every call is signed for ses, as the SDKs sign them.
call() {
	method=$1
	path=$2
	shift 2
	curl -fsS --aws-sigv4 aws:amz:us-east-1:ses --user smoke:smoke \
		-X "$method" -H "Content-Type: application/json" "$@" "http://$addr$path"
}

sent=$(call POST /v2/email/outbound-emails --data-binary '{
  "FromEmailAddress": "sender@example.com",
  "Destination": {"ToAddresses": ["smoke@example.com"]},
  "Content": {"Simple": {
    "Subject": {"Data": "smoke"},
    "Body": {"Text": {"Data": "smoke test"}}
  }}
}')
case $sent in
*'"MessageId":"'*) ;;
*)
	echo "sent $sent, want a MessageId" >&2
	exit 1
	;;
esac

listed=$(call GET '/_mailbox/messages?to=smoke@example.com')
case $listed in
*'"subject":"smoke"'*) ;;
*)
	echo "listed messages $listed, want the sent one" >&2
	exit 1
	;;
esac

if ! docker exec "$name" test -s /data/mailbox.db; then
	echo "no store at /data/mailbox.db" >&2
	exit 1
fi

echo "smoke test passed: $image"
