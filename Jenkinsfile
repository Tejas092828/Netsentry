pipeline {
    agent any

    environment {
        IMAGE_NAME = 'netsentry:1.0'
        PROJECT_DIR = '/home/ubuntu/Netsentry'
        HOME = '/home/ubuntu'
    }

    stages {
        stage('Source Check') {
            steps {
                sh '''
                    test -f ${PROJECT_DIR}/app.py
                    test -f ${PROJECT_DIR}/Dockerfile
                    test -f ${PROJECT_DIR}/k8s/deployment.yaml
                    test -f ${PROJECT_DIR}/k8s/service.yaml
                    echo "Source files verified"
                '''
            }
        }

        stage('Python Syntax Check') {
            steps {
                sh '''
                    python3 -c "import ast; ast.parse(open('${PROJECT_DIR}/app.py').read()); print('Python syntax OK')"
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t ${IMAGE_NAME} ${PROJECT_DIR}'
            }
        }

        stage('Load Image into Minikube') {
            steps {
                sh 'sudo -u ubuntu /usr/local/bin/minikube image load ${IMAGE_NAME}'
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                sh 'sudo -u ubuntu /usr/local/bin/minikube kubectl -- apply -f ${PROJECT_DIR}/k8s/deployment.yaml'
                sh 'sudo -u ubuntu /usr/local/bin/minikube kubectl -- apply -f ${PROJECT_DIR}/k8s/service.yaml'
                sh 'sudo -u ubuntu /usr/local/bin/minikube kubectl -- rollout status deployment/netsentry --timeout=120s'
            }
        }

        stage('Verify Deployment') {
            steps {
                sh 'sudo -u ubuntu /usr/local/bin/minikube kubectl -- get deployments'
                sh 'sudo -u ubuntu /usr/local/bin/minikube kubectl -- get pods'
                sh 'sudo -u ubuntu /usr/local/bin/minikube kubectl -- get services'
            }
        }
    }

    post {
        success {
            echo 'NETSENTRY CI/CD pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed. Check Console Output.'
        }
    }
}
