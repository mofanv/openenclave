#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## This script generates a header file with the following Open Enclave repository
## information: 
## branch name and last commit for use during the SDK loggin
##
##==============================================================================

config_header="$1"

cat > "$config_header" << EOF
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_REPOSITORY_CONFIG_H
#define OE_REPOSITORY_CONFIG_H

// The following defines will be overwritten by the configuration
// information read from the build environment.

EOF

branch_name=$(git branch | grep \* | cut -d ' ' -f2)
last_commit=$(git rev-parse HEAD)

# output branch name
printf '#define OE_REPO_BRANCH_NAME ' >> "$config_header"
if [ -z "$branch_name" ];then
    printf '"Not available"' >> "$config_header"
else
    printf '"%s"' "${branch_name}" >> "$config_header"
fi
printf '\n' >> "$config_header"

# output last commit hash value
printf '#define OE_REPO_LAST_COMMIT ' >> "$config_header"
if [ -z "$last_commit" ];then
    printf '"Not available"' >> "$config_header"
else
    printf '"%s"' "${last_commit}" >> "$config_header"
fi
printf '\n' >> "$config_header"

cat >> "$config_header" << EOF

#endif /* OE_REPOSITORY_CONFIG_H */
EOF
