#include "hijack/utils.h"
#include <cassert>
#include <iostream>
#include <string>

int main()
{
	std::string cgroup_mount_path = current_cgroup_mount_path();
	assert(cgroup_mount_path == "/sys/fs/cgroup");
}
