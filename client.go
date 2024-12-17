/*
v2 版本说明：
1. 添加了缓存 STS 临时凭证：
- STS 凭证获取后缓存，设置了 15 分钟有效期，避免频繁调用 STS 服务

2. 封装了上传和下载函数：
- uploadHandler
- downloadHandler

使用方式：
- 上传：POST /upload
curl -X POST http://localhost:8080/upload \
-F "bucketName=shiki4eva-04" \
-F "objectName=file.txt" \
-F "file=@file.txt"

- 下载：POST /download
curl -X POST http://localhost:8080/download \
  -F "bucketName=shiki4eva-04" \
  -F "objectName=file.txt" \
  -F "localFileName=downloaded.txt"
*/

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sts20150401 "github.com/alibabacloud-go/sts-20150401/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/gin-gonic/gin"
)

// 全局变量
var (
	stsClient      *sts20150401.Client
	ossClient      *oss.Client
	credentials    *sts20150401.AssumeRoleResponseBodyCredentials
	credentialsTTL time.Time
)

// 创建 STS 客户端
func CreateClient() (*sts20150401.Client, error) {
	accessKeyId := os.Getenv("OSS_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("OSS_ACCESS_KEY_SECRET")
	if accessKeyId == "" || accessKeySecret == "" {
		return nil, fmt.Errorf("环境变量 OSS_ACCESS_KEY_ID 和 OSS_ACCESS_KEY_SECRET 未设置")
	}

	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKeyId),
		AccessKeySecret: tea.String(accessKeySecret),
	}
	config.Endpoint = tea.String("sts.cn-shanghai.aliyuncs.com")

	return sts20150401.NewClient(config)
}

// 初始化 STS 客户端
func initSTSClient() {
	var err error
	stsClient, err = CreateClient()
	if err != nil {
		log.Fatalf("初始化 STS 客户端失败: %v", err)
	}
}

// 获取 STS 临时凭证
func getTemporaryCredentials() (*sts20150401.AssumeRoleResponseBodyCredentials, error) {
	// 如果未过期，直接返回
	if credentials != nil && time.Now().Before(credentialsTTL) {
		return credentials, nil
	}

	// 获取新的 STS 临时凭证
	resp, err := AssumeRole(stsClient)
	if err != nil {
		return nil, fmt.Errorf("获取临时凭证失败: %v", err)
	}

	credentials = resp

	// Expiration 字段获取过期时间
	expirationTime, err := time.Parse(time.RFC3339, tea.StringValue(credentials.Expiration))
	if err != nil {
		return nil, fmt.Errorf("解析凭证过期时间失败: %v", err)
	}
	credentialsTTL = expirationTime.Add(-1 * time.Minute) // 提前 1 分钟重新获取

	// 重新初始化 OSS 客户端
	endpoint := "https://oss-cn-shanghai.aliyuncs.com"
	ossClient, err = oss.New(endpoint, tea.StringValue(credentials.AccessKeyId), tea.StringValue(credentials.AccessKeySecret), oss.SecurityToken(tea.StringValue(credentials.SecurityToken)))
	if err != nil {
		return nil, fmt.Errorf("创建 OSS 客户端失败: %v", err)
	}

	return credentials, nil
}

// AssumeRole 获取临时凭证
func AssumeRole(client *sts20150401.Client) (*sts20150401.AssumeRoleResponseBodyCredentials, error) {
	request := &sts20150401.AssumeRoleRequest{
		DurationSeconds: tea.Int64(900),
		RoleArn:         tea.String("acs:ram::1571334090625876:role/ramosstest"),
		RoleSessionName: tea.String("RamTest"),
	}
	resp, err := client.AssumeRole(request)
	if err != nil {
		return nil, err
	}
	return resp.Body.Credentials, nil
}

// 上传文件到 OSS
func uploadHandler(c *gin.Context) {
	bucketName := c.PostForm("bucketName")
	objectName := c.PostForm("objectName")
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无法获取文件", "details": err.Error()})
		return
	}

	// 获取文件流
	fileContent, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开文件", "details": err.Error()})
		return
	}
	defer fileContent.Close()

	// 获取临时凭证
	if _, err := getTemporaryCredentials(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取临时凭证失败", "details": err.Error()})
		return
	}

	// 上传文件
	bucket, err := ossClient.Bucket(bucketName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取 bucket 失败", "details": err.Error()})
		return
	}

	if err := bucket.PutObject(objectName, fileContent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "上传文件失败", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "文件上传成功", "objectName": objectName})
}

// 下载文件到本地
func downloadHandler(c *gin.Context) {
	bucketName := c.PostForm("bucketName")
	objectName := c.PostForm("objectName")
	localFileName := c.PostForm("localFileName") // 客户端提供保存文件的本地路径

	// 获取临时凭证
	if _, err := getTemporaryCredentials(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取临时凭证失败", "details": err.Error()})
		return
	}

	// 获取 bucket
	bucket, err := ossClient.Bucket(bucketName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取 bucket 失败", "details": err.Error()})
		return
	}

	// 从 OSS 下载文件并保存到本地
	err = bucket.GetObjectToFile(objectName, localFileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "下载文件失败", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "文件下载成功",
		"objectName": objectName,
		"localFile":  localFileName,
	})
}

func main() {
	initSTSClient()
	r := gin.Default()

	// 上传文件
	r.POST("/upload", uploadHandler)

	// 下载文件
	r.POST("/download", downloadHandler)

	r.Run(":8080")
}

/*
v1 版本说明：
	gin中实现了uploadFileToOSS的调用
*/
// package main

// import (
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"os"

// 	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
// 	sts20150401 "github.com/alibabacloud-go/sts-20150401/v2/client"
// 	"github.com/alibabacloud-go/tea/tea"
// 	"github.com/aliyun/aliyun-oss-go-sdk/oss"
// 	"github.com/gin-gonic/gin"
// )

// // 初始化 STS 客户端
// func CreateClient() (*sts20150401.Client, error) {
// 	accessKeyId := os.Getenv("OSS_ACCESS_KEY_ID")
// 	accessKeySecret := os.Getenv("OSS_ACCESS_KEY_SECRET")
// 	if accessKeyId == "" || accessKeySecret == "" {
// 		return nil, fmt.Errorf("环境变量 OSS_ACCESS_KEY_ID 和 OSS_ACCESS_KEY_SECRET 未设置")
// 	}

// 	config := &openapi.Config{
// 		AccessKeyId:     tea.String(accessKeyId),
// 		AccessKeySecret: tea.String(accessKeySecret),
// 	}
// 	config.Endpoint = tea.String("sts.cn-shanghai.aliyuncs.com")

// 	return sts20150401.NewClient(config)
// }

// // AssumeRole 获取临时凭证
// func AssumeRole(client *sts20150401.Client) (*sts20150401.AssumeRoleResponseBodyCredentials, error) {
// 	assumeRoleRequest := &sts20150401.AssumeRoleRequest{
// 		DurationSeconds: tea.Int64(900), // 15min有效期
// 		Policy: tea.String(`{
// 			"Version": "1",
// 			"Statement": [
// 				{
// 					"Effect": "Allow",
// 					"Action": "*",
// 					"Resource": "*"
// 				}
// 			]
// 		}`),
// 		RoleArn:         tea.String("acs:ram::1571334090625876:role/ramosstest"),
// 		RoleSessionName: tea.String("RamTest"),
// 	}

// 	resp, err := client.AssumeRole(assumeRoleRequest)
// 	if err != nil {
// 		return nil, fmt.Errorf("获取临时凭证失败: %v", err)
// 	}

// 	return resp.Body.Credentials, nil
// }

// // uploadFile 用于上传本地文件到 OSS
// func uploadFileToOSS(bucketName, objectName, localFileName string) error {
// 	// 1: 获取临时授权
// 	stsClient, err := CreateClient()
// 	if err != nil {
// 		return err
// 	}

// 	credentials, err := AssumeRole(stsClient)
// 	if err != nil {
// 		return err
// 	}

// 	// 2: 使用临时授权创建 OSS 客户端
// 	endpoint := "https://oss-cn-shanghai.aliyuncs.com"
// 	ossClient, err := oss.New(endpoint, tea.StringValue(credentials.AccessKeyId), tea.StringValue(credentials.AccessKeySecret), oss.SecurityToken(tea.StringValue(credentials.SecurityToken)))
// 	if err != nil {
// 		return fmt.Errorf("创建 OSS 客户端失败: %v", err)
// 	}

// 	// 3: 上传文件
// 	bucket, err := ossClient.Bucket(bucketName)
// 	if err != nil {
// 		return fmt.Errorf("获取 bucket 失败: %v", err)
// 	}

// 	err = bucket.PutObjectFromFile(objectName, localFileName)
// 	if err != nil {
// 		return fmt.Errorf("上传文件失败: %v", err)
// 	}

// 	log.Printf("文件上传成功: %s/%s", bucketName, objectName)
// 	return nil
// }

// // Gin 服务的主函数
// func main() {
// 	r := gin.Default()

// 	// upload
// 	r.POST("/upload", func(c *gin.Context) {
// 		// 获取 bucketName 和 objectName
// 		bucketName := c.PostForm("bucketName")
// 		objectName := c.PostForm("objectName")

// 		// 获取上传的文件
// 		file, err := c.FormFile("file")
// 		if err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "文件上传失败", "details": err.Error()})
// 			return
// 		}

// 		// 保存文件到本地
// 		localFileName := "./" + file.Filename
// 		if err := c.SaveUploadedFile(file, localFileName); err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存文件失败", "details": err.Error()})
// 			return
// 		}

// 		// 上传文件到 OSS
// 		if err := uploadFileToOSS(bucketName, objectName, localFileName); err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "上传到 OSS 失败", "details": err.Error()})
// 			return
// 		}

// 		// 返回成功消息
// 		c.JSON(http.StatusOK, gin.H{
// 			"message":    "文件上传成功",
// 			"bucketName": bucketName,
// 			"objectName": objectName,
// 		})
// 	})

//		// 启动服务
//		r.Run(":8080") // 监听 8080 端口
//	}