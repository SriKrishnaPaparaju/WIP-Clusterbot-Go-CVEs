package print

import (
	"os"
	trace "github.com/openshift/origin/tools/depcheck/pkg/cmd"
	flags "github.com/openshift/origin/tools/depcheck/pkg/graph"
	"fmt"
	gographviz "github.com/awalterschulze/gographviz"
	"strings"
	sql "database/sql"
	json "encoding/json"
	_ "github.com/lib/pq"
)

type VulnReport struct {
    Name string
    Probable_vuln []ProbableVulnerability
}

type ProbableVulnerability struct {
	Dependency_Name	string
	Repo_name		string
	Path_from_PR	[]string
	Flagged_url 	string
	Event_type		string
	Created_at		string
	Updated_at		string
	Closed_date		string
	Creator_name	string
	Creator_url		string
	CVE				string
	Issue_fixed		string
    CVE_published_date	string	
}


func GetVulnReport(pr string, entrypoints []string) string {

	report := VulnReport{Name: pr}
	if entrypoints == nil || len(entrypoints) == 0 {
		entrypoints = []string{os.Getenv("BOT_SCAN_REPO_ENTRY_POINTSTOKEN")}
	}
	fmt.Printf("received entry points are %s", entrypoints)
	 graphflags := flags.GraphFlags{
		Openshift: true,
		RepoImportPath: pr,
		Entrypoints: entrypoints,
	 }
	 graphOptions, err := graphflags.ToOptions(os.Stdout, os.Stderr)
	 if err != nil {
		fmt.Print(err)
	}
	vulnerabilities := getVulnerabilities(pr, *graphOptions, "silly.dot")
	report.Probable_vuln = vulnerabilities
	reportstring, _ := json.Marshal(report)
	fmt.Printf(string(reportstring))
	return string(reportstring)
}


func getVulnerabilities(pr string, graphOptions flags.GraphOptions, outputGraphName string) []ProbableVulnerability {
	// 1. For a PR, create a .dot file for the capturing tree of dependencies
	   graphdata := trace.ExportTraceGraph(graphOptions, outputGraphName)

	   // 2. Convert .dot file content to a parsable graph datastructure
	   graphAst, _ := gographviz.ParseString(string(graphdata))
	   graph := gographviz.NewGraph()
		if err := gographviz.Analyse(graphAst, graph); err != nil {
			panic(err)
		}

		// 3. Get the list of all the dependencies that emanate for this PR
		dependencyList := getAllDependencyNames(graph)
		// 4. Check against the database if any of the dependencies (for this PR) associated either with a probable vulnerability / CVE
		vulns := findDependenciesWithVulnerabilties(*graph, dependencyList)
		for i, _ := range vulns {
			var pathnodes []string
			recursive(*graph, vulns[i].Dependency_Name, &pathnodes,0)			
			vulns[i].Path_from_PR = pathnodes
			vulns[i].Dependency_Name = getDependencyName(*graph, vulns[i].Dependency_Name)
		}
		return vulns 
	}

	func recursive(graph gographviz.Graph, targetnode string, pathnodes *[]string, count int)  {
		count = count +1

		node := getEdgesReachingADependency(graph, targetnode, pathnodes) 

		if len(node) < 1 {
			return 
		}
		*pathnodes = append(*pathnodes, getDependencyName(graph,node))
		if !strings.EqualFold(node, "0") && count < 7 {
			recursive(graph, node, pathnodes, count)
		} else
		{
			return
		}
	}

/*
	func recursive(graph gographviz.Graph, targetdependency string, pathnodes *[]string, count int)  {
		count = count +1
		node := getEdgesReachingADependency(graph, targetdependency) 
		if len(node) < 1 {
			return 
		}
		*pathnodes = append(*pathnodes, node)
		if !strings.EqualFold(node, "0") || count < 7 {
			recursive(graph, getDependencyName(graph, node), pathnodes, count)
		} else
		{
			return
		}
	}
*/

var   (
	id int
	flagged_url 	string
	repo_name 		string
	event_type		string
	created_at		string
	updated_at		string
	closed_date		string
	creator_name	string
	creator_url		string
	cve				string
	issue_fixed		string
	cve_published_date	string
)

func findDependenciesWithVulnerabilties(graph gographviz.Graph, alldependencies []string) []ProbableVulnerability  {
	var listOfDependenciesWithVulnerabilities []ProbableVulnerability 

	connStr := "postgres://postgres:sillypass123@localhost/postgres?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Print(err)
	}
	rows, err := db.Query("SELECT id, flagged_url, repo_name, event_type,  created_at_string, updated_at_string, closed_date, creator_name, creator_url, cve, issue_fixed,  cve_published_date FROM \"security-data\".\"probable-data\"")
	defer rows.Close()
	defer db.Close()

	for rows.Next() {
		err := rows.Scan(&(id), &(flagged_url), &(repo_name),&(event_type),&(created_at),&(updated_at),&(closed_date),&(creator_name),&(creator_url),&(cve),&(issue_fixed),&(cve_published_date))
		if err != nil {
			fmt.Print(err)
		}
		ifpresent, matchingdependencyname := checkDependencyName (graph, repo_name, alldependencies)
		if ifpresent {
			probableVuln := ProbableVulnerability{
				Flagged_url: flagged_url, 
				Repo_name: repo_name,
				Dependency_Name: matchingdependencyname,
				Event_type: event_type,
				Created_at: created_at,
				Updated_at: updated_at,
				Closed_date: closed_date,
				Creator_name: creator_name,
				Creator_url: creator_url,
				CVE: cve,
				Issue_fixed: issue_fixed,
				CVE_published_date: cve_published_date,	
				}			
			listOfDependenciesWithVulnerabilities = append(listOfDependenciesWithVulnerabilities, probableVuln)
		}
	}
	err = rows.Err()
	if err != nil {
		fmt.Print(err)
	}
	return listOfDependenciesWithVulnerabilities
}	

func checkDependencyName (graph gographviz.Graph, repo_name string, alldependencies []string) (bool, string) {
	var returnvalue bool = false
	var matchingdependencyname string
	for _, name := range alldependencies {
		dependencyname := getDependencyName(graph,name)
		if strings.Contains(dependencyname, repo_name) {
			returnvalue = true
			matchingdependencyname = name
		}
	}
	return returnvalue, matchingdependencyname
}

func getAllDependencyNames(graph *gographviz.Graph) []string {
	var listOfDependencies []string
	for _, node := range graph.Nodes.Nodes {
		listOfDependencies = append(listOfDependencies, node.Name)
	}
	return listOfDependencies
}

func getDependencyName(graph gographviz.Graph,  nodename string) string {
	dependencyname := "-none-"

	for _, node := range graph.Nodes.Nodes {
		if strings.Contains(node.Name, nodename) {
				dependencyname = node.Attrs["label"]
				break
			}
		}
	return dependencyname	
}

/*
func getEdgesReachingADependency(graph gographviz.Graph, targetnode string) string {
	var	returnode string
	for _, edge := range graph.Edges.Edges {
		dstDependencyName := getDependencyName(graph, edge.Dst)

		if strings.Contains(dstDependencyName, targetnode) {
			returnode = edge.Src
			break
		}
	}
	return returnode
}
*/

func checkForString(findstring string, values []string) bool {
	var returnvalue bool
	for index, _ := range values {
		if findstring == values[index] {
			returnvalue = true
			break
		}
	}	
	return returnvalue
}

func getEdgesReachingADependency(graph gographviz.Graph, targetnode string, alreadytraverednodes *[]string) string {

	var	returnode string
	for _, edge := range graph.Edges.Edges {

		if strings.EqualFold(targetnode, edge.Dst) {
			// Check if this source is already traversed
			if !checkForString(getDependencyName(graph,edge.Src), *alreadytraverednodes) {
				returnode = edge.Src
				break
			}

		}
	}
	return returnode
}

