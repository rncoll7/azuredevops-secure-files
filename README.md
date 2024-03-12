# Azure DevOps secureFiles uploader

## About The Project
Tired of manual work to update secure files on Azure DevOps, 
this project trys to solve this problem and automate the process.

## Setup

### Build
Before use you may need to build the project
```sh
  go build SecureFilesAzureDevOpsUploader.go
```
### Expected env vars

```sh
export AZURE_ORGANIZATION=""
export AZURE_PROJECT_ID=""
export AZURE_DEVOPS_TOKEN=""
```

## Use

### Create and give pipeline permission
```sh
  ./SecureFilesAzureDevOpsUploader "/path/to/file" "secure_file_name_post_upload" "name_of_pipeline"
```
> in this example
> 
> 1st `"/path/to/file"` should by replaced by local file location path
>
> 2nd `"secure_file_name_post_upload"` is the name of file before upload
>
> 3rd..or more `"name_of_pipeline"` is the name of pipeline who will use this file, this can by multiple parameter

## Reference
 - https://learn.microsoft.com/en-us/rest/api/azure/devops/approvalsandchecks/pipeline-permissions/update-pipeline-permisions-for-resource?view=azure-devops-rest-7.2&tabs=HTTP
 - There is no documentation for securefile on microsoft site