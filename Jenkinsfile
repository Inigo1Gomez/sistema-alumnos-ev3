// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Pipeline DevSecOps:
//   Build -> Test -> Security Review (SAST: Bandit) -> Dependency Management (SCA: pip-audit)
//   -> Deploy Staging -> DAST - OWASP ZAP -> Deploy Producción (solo si TODO lo anterior quedó en verde)
//
// Las herramientas de seguridad marcan el build como UNSTABLE (amarillo) cuando encuentran hallazgos;
// el "gate" de producción impide desplegar un build UNSTABLE o FAILED.
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // [SEGURIDAD] Revisión del código (SAST) con Bandit
        stage('Security Review (SAST)') {
            steps {
                // Reportes completos (todas las severidades) para el registro y la trazabilidad
                sh 'bandit -f json -o reports/bandit.json app.py || true'
                sh 'bandit -f txt -o reports/bandit.txt app.py || true'
                sh 'cat reports/bandit.txt'
                // Control de calidad: hallazgos Medium o High dejan el build UNSTABLE
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE',
                           message: 'Bandit encontró hallazgos de severidad Medium/High') {
                    sh 'bandit -q -ll app.py'
                }
            }
        }

        // [SEGURIDAD] Dependencias con vulnerabilidades conocidas (SCA) con pip-audit
        stage('Dependency Management') {
            steps {
                sh 'pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true'
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE',
                           message: 'pip-audit encontró dependencias con CVE') {
                    sh '''
                        estado=0
                        pip-audit -r requirements.txt > reports/pip-audit.txt 2>&1 || estado=$?
                        cat reports/pip-audit.txt
                        exit $estado
                    '''
                }
            }
        }

        // [ZAP] Despliegue en staging para el análisis dinámico
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        // [ZAP] Pruebas automatizadas de seguridad (DAST) con OWASP ZAP sobre staging
        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    def estado = sh(returnStatus: true, script: 'python3 scripts/zap_scan.py http://jenkins:5001')
                    if (estado == 2) {
                        unstable('OWASP ZAP encontró alertas de riesgo High/Medium (ver reports/zap-report.html)')
                    } else if (estado != 0) {
                        error("El escaneo de OWASP ZAP falló (código ${estado})")
                    }
                }
            }
        }

        stage('Deploy Producción') {
            // [GATE] Producción solo recibe builds sin hallazgos: pruebas, SAST, SCA y DAST en verde
            when {
                beforeAgent true
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        unstable {
            echo 'Build UNSTABLE: hay hallazgos de seguridad. Producción NO se actualizó (gate).'
        }
    }
}
