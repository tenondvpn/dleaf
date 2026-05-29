#if __APPLE__
    #include <TargetConditionals.h>
    #include <asl.h>
    void leaf_mobile_log(const char *message);
#elif __ANDROID__
//    #include <android/log.h>
#endif
