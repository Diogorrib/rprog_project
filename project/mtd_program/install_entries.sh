PYTHON=$(which python3 || which python)
$PYTHON mycontroller.py \
    --p4info build/router.p4.p4info.txtpb build/switch.p4.p4info.txtpb \
    --bmv2-json build/router.json build/switch.json
