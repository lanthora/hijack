// SPDX-License-Identifier: Apache-2.0
#include <fstream>
#include <sstream>
#include <string>

std::string current_cgroup_mount_path()
{
	std::ifstream infile("/proc/self/mounts");
	std::string line;

	while (std::getline(infile, line)) {
		std::string type, path;
		std::istringstream iss(line);

		if (!(iss >> type))
			break;

		if (type != "cgroup2")
			continue;

		if (!(iss >> path))
			break;

		return path;
	}

	return "";
}
