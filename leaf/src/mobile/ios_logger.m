#import <Foundation/Foundation.h>
#import <os/log.h>
#include <stdio.h>

static void leaf_append_file_log(NSString *line) {
    NSURL *containerURL = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:@"group.com.seth.sethvpn"];
    if (containerURL == nil) {
        return;
    }

    NSURL *logURL = [containerURL URLByAppendingPathComponent:@"packet_tunnel.log"];
    NSString *entry = [NSString stringWithFormat:@"%@ [LEAF] %@",
                       [[NSDate date] descriptionWithLocale:nil],
                       line];
    NSData *data = [entry dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil) {
        return;
    }

    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:[logURL path]]) {
        [fileManager createFileAtPath:[logURL path] contents:nil attributes:nil];
    }

    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:[logURL path]];
    if (handle == nil) {
        return;
    }
    @try {
        [handle seekToEndOfFile];
        [handle writeData:data];
    } @finally {
        [handle closeFile];
    }
}

void leaf_mobile_log(const char *message) {
    if (message == NULL) {
        return;
    }

    NSString *line = [NSString stringWithUTF8String:message];
    if (line == nil) {
        line = @"<invalid utf8 log line>";
    }

    NSLog(@"%@", line);
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_INFO, "%{public}@", line);
    leaf_append_file_log(line);
    fprintf(stderr, "%s", message);
    fflush(stderr);
}
