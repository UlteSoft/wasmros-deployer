/** @file native_launch_verifier.c
 *  @brief Change disposable guest fixtures between the two real verifier runs.
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 5)
        return 90;
    if (unlink("/run/withdraw-signer") == 0) {
        if (unlink("/trust/launch-only.pem") != 0)
            return 91;
    } else if (errno != ENOENT) {
        return 92;
    }
    if (unlink("/run/replace-image") == 0) {
        if (rename("/bundle/replacement", "/bundle/swap-provider") != 0)
            return 93;
    } else if (errno != ENOENT) {
        return 94;
    }
    execv("/bin/uwvm2-ros", argv);
    return 95;
}
