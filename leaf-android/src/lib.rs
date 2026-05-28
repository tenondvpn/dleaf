use jni::{
    objects::{JClass, JString},
    sys, JNIEnv,
};

unsafe fn jstring_to_string(env: JNIEnv, value: JString) -> String {
    env.get_string(value)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

unsafe fn run_leaf(env: JNIEnv, config_path: JString) {
    let config_path = jstring_to_string(env, config_path);
    let opts = leaf::StartOptions {
        config: leaf::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::MultiThreadAuto(1024 * 1024),
    };
    leaf::start(0, opts).unwrap();
}

fn stop_leaf() -> sys::jboolean {
    if leaf::shutdown(0) {
        sys::JNI_TRUE
    } else {
        sys::JNI_FALSE
    }
}

fn is_leaf_running() -> sys::jboolean {
    if leaf::is_running(0) {
        sys::JNI_TRUE
    } else {
        sys::JNI_FALSE
    }
}

fn java_string(env: JNIEnv, value: String) -> sys::jstring {
    env.new_string(value)
        .expect("Couldn't create java string!")
        .into_inner()
}

unsafe fn set_client_pk(env: JNIEnv, pk: JString) {
    leaf::set_pk(jstring_to_string(env, pk));
}

unsafe fn set_client_pk_hash(env: JNIEnv, pk: JString) {
    leaf::set_pk_hash(jstring_to_string(env, pk));
}

unsafe fn push_client_msg(env: JNIEnv, msg: JString) {
    leaf::push_client_msg(jstring_to_string(env, msg));
}

unsafe fn push_transaction_msg(env: JNIEnv, msg: JString) {
    leaf::push_transaction_msg(jstring_to_string(env, msg));
}

unsafe fn push_sell_msg(env: JNIEnv, msg: JString) {
    leaf::push_sell_msg(jstring_to_string(env, msg));
}

unsafe fn push_order_msg(env: JNIEnv, msg: JString) {
    leaf::push_order_msg(jstring_to_string(env, msg));
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_runLeaf(
    env: JNIEnv,
    _: JClass,
    config_path: JString,
) {
    run_leaf(env, config_path);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_stopLeaf(
    _: JNIEnv,
    _: JClass,
) -> sys::jboolean {
    stop_leaf()
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_isLeafRunning(
    _: JNIEnv,
    _: JClass,
) -> sys::jboolean {
    is_leaf_running()
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_getStatus(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    java_string(env, leaf::get_status())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_getNodes(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    java_string(env, leaf::get_nodes())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_setClientPk(
    env: JNIEnv,
    _: JClass,
    pk: JString,
) {
    set_client_pk(env, pk);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_setClientPkHash(
    env: JNIEnv,
    _: JClass,
    pk: JString,
) {
    set_client_pk_hash(env, pk);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushClientMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_client_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_getResponseMsg(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    java_string(env, leaf::get_response_msg())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushTransactionMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_transaction_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushSellMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_sell_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushOrderMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_order_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_runLeaf(
    env: JNIEnv,
    class: JClass,
    config_path: JString,
) {
    Java_com_leaf_example_aleaf_SimpleVpnService_runLeaf(env, class, config_path);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_stopLeaf(
    env: JNIEnv,
    class: JClass,
) -> sys::jboolean {
    Java_com_leaf_example_aleaf_SimpleVpnService_stopLeaf(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_isLeafRunning(
    env: JNIEnv,
    class: JClass,
) -> sys::jboolean {
    Java_com_leaf_example_aleaf_SimpleVpnService_isLeafRunning(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_getStatus(
    env: JNIEnv,
    class: JClass,
) -> sys::jstring {
    Java_com_leaf_example_aleaf_SimpleVpnService_getStatus(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_getNodes(
    env: JNIEnv,
    class: JClass,
) -> sys::jstring {
    Java_com_leaf_example_aleaf_SimpleVpnService_getNodes(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_setClientPk(
    env: JNIEnv,
    class: JClass,
    pk: JString,
) {
    Java_com_leaf_example_aleaf_SimpleVpnService_setClientPk(env, class, pk);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_setClientPkHash(
    env: JNIEnv,
    class: JClass,
    pk: JString,
) {
    Java_com_leaf_example_aleaf_SimpleVpnService_setClientPkHash(env, class, pk);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushClientMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushClientMsg(env, class, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_getResponseMsg(
    env: JNIEnv,
    class: JClass,
) -> sys::jstring {
    Java_com_leaf_example_aleaf_client_getResponseMsg(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushTransactionMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushTransactionMsg(env, class, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushSellMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushSellMsg(env, class, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushOrderMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushOrderMsg(env, class, msg);
}
