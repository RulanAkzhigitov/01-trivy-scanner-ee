package trivy

import (
	"strings"
)

func BuildTrivyArgs(params map[string]interface{}, serverURL, target string) []string {
	args := []string{"image", "--server", serverURL, "--format", "json"}

	if scanners, ok := params["scanners"].([]interface{}); ok {
		scannerList := make([]string, len(scanners))
		for i, s := range scanners {
			scannerList[i] = s.(string)
		}
		args = append(args, "--scanners", strings.Join(scannerList, ","))
	}
	if imgScanners, ok := params["image_config_scanners"].([]interface{}); ok && len(imgScanners) > 0 {
		scannerList := make([]string, len(imgScanners))
		for i, s := range imgScanners {
			scannerList[i] = s.(string)
		}
		args = append(args, "--image-config-scanners", strings.Join(scannerList, ","))
	}
	if severity, ok := params["severity"].([]interface{}); ok {
		sevList := make([]string, len(severity))
		for i, s := range severity {
			sevList[i] = s.(string)
		}
		args = append(args, "--severity", strings.Join(sevList, ","))
	}
	if ignoreUnfixed, ok := params["ignore_unfixed"].(bool); ok && ignoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}
	if priority, ok := params["detection_priority"].(string); ok && priority != "" {
		args = append(args, "--detection-priority", priority)
	}
	if pkgTypes, ok := params["pkg_types"].([]interface{}); ok {
		types := make([]string, len(pkgTypes))
		for i, t := range pkgTypes {
			types[i] = t.(string)
		}
		args = append(args, "--pkg-types", strings.Join(types, ","))
	}
	if pkgRels, ok := params["pkg_relationships"].([]interface{}); ok {
		rels := make([]string, len(pkgRels))
		for i, r := range pkgRels {
			rels[i] = r.(string)
		}
		args = append(args, "--pkg-relationships", strings.Join(rels, ","))
	}

	args = append(args, target)
	return args
}

func HasKey(m map[string]interface{}, key string) bool {
	_, ok := m[key]
	return ok
}
