<?php
class NaiveBayesClassifier {
    private $training_data = [];
    private $class_probabilities = [];
    private $feature_probabilities = [];
    private $confidence = 0;
    private $threat_patterns = [];
    
    public function __construct() {
        // Load training data
        $this->loadTrainingData();
    }
    
    private function loadTrainingData() {
        // Realistic training data based on common network patterns
        $this->training_data = [
            // Malicious patterns
            ['malicious' => [6, 1500, 80, 80, 1500]],  // Large packet size, same ports
            ['malicious' => [6, 1400, 80, 445, 1400]], // Large packet size, SMB port
            ['malicious' => [6, 1000, 80, 22, 1000]],  // Large packet size, SSH port
            ['malicious' => [6, 1200, 80, 3389, 1200]], // Large packet size, RDP port
            ['malicious' => [17, 512, 137, 138, 512]],  // UDP, NetBIOS ports
            ['malicious' => [6, 1300, 80, 1433, 1300]], // MSSQL port
            ['malicious' => [6, 1100, 80, 3306, 1100]], // MySQL port
            ['malicious' => [6, 900, 80, 5900, 900]],   // VNC port
            ['malicious' => [6, 1600, 80, 1434, 1600]], // MS-SQL Monitor
            
            // Benign patterns
            ['benign' => [6, 64, 80, 443, 64]],  // Small packet size, HTTPS
            ['benign' => [6, 64, 80, 80, 64]],   // Small packet size, HTTP
            ['benign' => [6, 64, 80, 53, 64]],   // Small packet size, DNS
            ['benign' => [6, 64, 80, 25, 64]],   // Small packet size, SMTP
            ['benign' => [6, 64, 80, 110, 64]],  // Small packet size, POP3
            ['benign' => [6, 64, 80, 123, 64]],  // NTP
            ['benign' => [6, 64, 80, 161, 64]],  // SNMP
            ['benign' => [6, 64, 80, 67, 64]],   // DHCP
            ['benign' => [6, 64, 80, 68, 64]],   // DHCP
        ];
        
        // Add more aggressive threat detection rules
        $this->threat_patterns = [
            // Large packet sizes
            ['size' => 1000, 'type' => 'malicious'],
            ['size' => 800, 'type' => 'suspicious'],
            
            // Suspicious port combinations
            ['ports' => [22, 3389], 'type' => 'malicious'],
            ['ports' => [137, 138], 'type' => 'malicious'],
            ['ports' => [1433, 3306], 'type' => 'malicious'],
            
            // Common attack ports
            ['ports' => [21, 22, 23, 25, 53, 80, 443], 'type' => 'suspicious']
        ];
        
        $this->calculateProbabilities();
    }
    
    private function calculateProbabilities() {
        // Calculate class probabilities based on training data
        $total_samples = count($this->training_data);
        $malicious_count = 0;
        $benign_count = 0;
        
        foreach ($this->training_data as $data) {
            foreach ($data as $class => $features) {
                if ($class === 'malicious') {
                    $malicious_count++;
                } else {
                    $benign_count++;
                }
            }
        }
        
        $this->class_probabilities['malicious'] = ($malicious_count + 1) / ($total_samples + 2);
        $this->class_probabilities['benign'] = ($benign_count + 1) / ($total_samples + 2);
        
        // Calculate feature probabilities
        foreach ($this->training_data as $data) {
            foreach ($data as $class => $features) {
                foreach ($features as $index => $value) {
                    if (!isset($this->feature_probabilities[$index])) {
                        $this->feature_probabilities[$index] = [
                            'malicious' => [],
                            'benign' => []
                        ];
                    }
                    $this->feature_probabilities[$index][$class][] = $value;
                }
            }
        }
    }
    
    public function predict($features) {
        $malicious_prob = $this->class_probabilities['malicious'];
        $benign_prob = $this->class_probabilities['benign'];
        
        foreach ($features as $index => $value) {
            if (isset($this->feature_probabilities[$index])) {
                $malicious_prob *= $this->calculateFeatureProb($index, $value, 'malicious');
                $benign_prob *= $this->calculateFeatureProb($index, $value, 'benign');
            }
        }
        
        // Check for aggressive threat detection rules
        foreach ($this->threat_patterns as $pattern) {
            if (isset($pattern['size']) && $features[4] >= $pattern['size']) {
                if ($pattern['type'] === 'malicious') {
                    $malicious_prob *= 2;
                } elseif ($pattern['type'] === 'suspicious') {
                    $malicious_prob *= 1.5;
                }
            } elseif (isset($pattern['ports'])) {
                if (in_array($features[2], $pattern['ports']) && in_array($features[3], $pattern['ports'])) {
                    if ($pattern['type'] === 'malicious') {
                        $malicious_prob *= 2;
                    } elseif ($pattern['type'] === 'suspicious') {
                        $malicious_prob *= 1.5;
                    }
                }
            }
        }
        
        $this->confidence = $malicious_prob / ($malicious_prob + $benign_prob);
        
        // Apply threshold for classification
        if ($this->confidence > 0.7) {
            return 'malicious';
        } elseif ($this->confidence < 0.3) {
            return 'benign';
        }
        
        // If confidence is between 0.3 and 0.7, classify based on probability
        return $malicious_prob > $benign_prob ? 'malicious' : 'benign';
    }
    
    private function calculateFeatureProb($index, $value, $class) {
        $values = $this->feature_probabilities[$index][$class];
        $count = count($values);
        $matches = count(array_filter($values, function($v) use ($value) {
            return abs($v - $value) <= 10; // Allow some tolerance
        }));
        
        return ($matches + 1) / ($count + 2); // Laplace smoothing
    }
    
    public function get_confidence() {
        return $this->confidence;
    }
}
?>