package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var organization string
var projectId string
var token string

const apiVersion = "7.1-preview.1"

func main() {
	path := os.Args[1]
	name := os.Args[2]
	pipelineNames := os.Args[3:]
	organization = os.Getenv("AZURE_ORGANIZATION")
	projectId = os.Getenv("AZURE_PROJECT_ID")
	token = os.Getenv("AZURE_DEVOPS_TOKEN")

	err := uploadSecureFile(path, name, pipelineNames)
	if err != nil {
		log.Fatalf("Fatal: %v\n", err)
	}
}

func uploadSecureFile(path string, name string, pipelineNames []string) error {

	file_bytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	file_hash := Hash(file_bytes)

	secureFilesList, err := getSecureFiles(token)
	if err != nil {
		return err
	}

	var secureFile SecureFile
	for _, _secureFile := range secureFilesList.Value {
		if _secureFile.Name == name {
			secureFile = _secureFile
			break
		}
	}

	if secureFile.Id != "" {
		log.Printf("Securefile found(%s): %s\n", secureFile.Name, secureFile.Id)
		if secureFile.Properties.Hash == file_hash {
			log.Printf("file not changed %s\n", file_hash)
		}

		err = deleteSecureFiles(secureFile)
		if err != nil {
			return err
		}
	}

	secureFile, err = createSecureFiles(file_bytes, name)
	if err != nil {
		return err
	}
	log.Printf("Securefile created(%s): %s\n", secureFile.Name, secureFile.Id)
	secureFile.Properties.Hash = file_hash

	err = updateSecureFiles(secureFile)
	if err != nil {
		return err
	}

	pipelinesList, err := getPipelines(token)
	if err != nil {
		return err
	}

	var pipelines []Pipeline
	for _, _pipeline := range pipelinesList.Value {
		for _, pipelineName := range pipelineNames {
			if _pipeline.Name == pipelineName {
				pipelines = append(pipelines, _pipeline)
				log.Printf("Pipeline found(%s): %d\n", _pipeline.Name, _pipeline.Id)
			}
		}

	}

	if len(pipelines) > 0 {
		err = updatePipelinesSecurefilePermissions(secureFile, pipelines)
		if err != nil {
			return err
		}
	}

	return nil
}

func getSecureFiles(token string) (SecureFileList, error) {

	path := fmt.Sprintf("distributedtask/securefiles")
	params := fmt.Sprintf("api-version=%s", apiVersion)
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/%s?%s", organization, projectId, path, params)
	method := "GET"
	result := SecureFileList{}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return result, fmt.Errorf("getSecureFiles build error: %v", err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(":%s", token)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basic))

	res, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("getSecureFiles request error: %v", err)
	}

	//goland:noinspection ALL
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("getSecureFiles read error: %v", err)
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, fmt.Errorf("getSecureFiles unmarshal error: %v", err)
	}

	return result, nil
}

func deleteSecureFiles(secureFile SecureFile) error {

	path := fmt.Sprintf("distributedtask/securefiles/%s", secureFile.Id)
	params := fmt.Sprintf("api-version=%s", apiVersion)
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/%s?%s", organization, projectId, path, params)
	method := "DELETE"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return fmt.Errorf("deleteSecureFiles build error: %v", err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(":%s", token)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basic))

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deleteSecureFiles request error: %v", err)
	}

	if res.StatusCode != 204 {
		return fmt.Errorf("deleteSecureFiles status not expected: %d", res.StatusCode)
	}

	return nil
}

func createSecureFiles(file []byte, name string) (SecureFile, error) {

	path := fmt.Sprintf("distributedtask/securefiles")
	params := fmt.Sprintf("api-version=%s&name=%s", apiVersion, name)
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/%s?%s", organization, projectId, path, params)
	method := "POST"
	result := SecureFile{}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, bytes.NewReader(file))
	if err != nil {
		return result, fmt.Errorf("createSecureFiles build error: %v", err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(":%s", token)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basic))
	req.Header.Add("Content-Type", "application/octet-stream")

	res, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("createSecureFiles request error: %v", err)
	}

	//goland:noinspection ALL
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("createSecureFiles read error: %v", err)
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, fmt.Errorf("createSecureFiles unmarshal error: %v", err)
	}

	return result, nil
}

func updateSecureFiles(secureFile SecureFile) error {

	path := fmt.Sprintf("distributedtask/securefiles/%s", secureFile.Id)
	params := fmt.Sprintf("api-version=%s", apiVersion)
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/%s?%s", organization, projectId, path, params)
	method := "PATCH"

	payload, err := json.Marshal(secureFile)
	if err != nil {
		return fmt.Errorf("updateSecureFiles marshal error: %v", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("updateSecureFiles build error: %v", err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(":%s", token)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basic))
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("updateSecureFiles request error: %v", err)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("updateSecureFiles status not expected: %d", res.StatusCode)
	}

	return nil
}

func getPipelines(token string) (PipelineList, error) {

	path := fmt.Sprintf("pipelines")
	params := fmt.Sprintf("api-version=%s", apiVersion)
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/%s?%s", organization, projectId, path, params)
	method := "GET"
	result := PipelineList{}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return result, fmt.Errorf("getPipelines build error: %v", err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(":%s", token)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basic))

	res, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("getPipelines request error: %v", err)
	}

	//goland:noinspection ALL
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return result, fmt.Errorf("getPipelines read error: %v", err)
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, fmt.Errorf("getPipelines unmarshal error: %v", err)
	}

	return result, nil
}

func updatePipelinesSecurefilePermissions(secureFile SecureFile, pipelines []Pipeline) error {

	path := fmt.Sprintf("pipelines/pipelinePermissions/securefile/%s", secureFile.Id)
	params := fmt.Sprintf("api-version=%s", apiVersion)
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/%s?%s", organization, projectId, path, params)
	method := "PATCH"

	var authorizes []Authorize
	for _, pipeline := range pipelines {
		authorizes = append(authorizes, Authorize{Authorized: true, Id: pipeline.Id})
	}

	payload, err := json.Marshal(Permissions{Pipelines: authorizes})
	if err != nil {
		return fmt.Errorf("updatePipelinesSecurefilePermissions marshal error: %v", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("updatePipelinesSecurefilePermissions build error: %v", err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(":%s", token)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basic))
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("updatePipelinesSecurefilePermissions request error: %v", err)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("updatePipelinesSecurefilePermissions status not expected: %d", res.StatusCode)
	}

	return nil
}

func Hash(_bytes []byte) string {
	hasher := sha1.New()
	hasher.Write(_bytes)
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

type SecureFileList struct {
	Count int          `json:"count"`
	Value []SecureFile `json:"value"`
}

type SecureFile struct {
	Id         string     `json:"id"`
	Name       string     `json:"name"`
	Properties Properties `json:"properties"`
}

type Properties struct {
	Hash string `json:"hash"`
}

type PipelineList struct {
	Count int        `json:"count"`
	Value []Pipeline `json:"value"`
}

type Pipeline struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

type Permissions struct {
	Pipelines []Authorize `json:"pipelines"`
}

type Authorize struct {
	Authorized bool `json:"authorized"`
	Id         int  `json:"id"`
}
