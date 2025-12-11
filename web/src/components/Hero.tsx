import React from 'react';
import { getTotalTestCount } from '../data/vulnerabilities';

interface HeroProps {
    onExplore: () => void;
    onAnalyze: () => void;
}

export const Hero: React.FC<HeroProps> = ({ onExplore, onAnalyze }) => {
    const totalTests = getTotalTestCount();

    return (
        <section className="hero" id="hero">
            <div className="container">
                <div className="hero-content">
                    <div className="hero-badge">
                        <span>🛡️</span>
                        <span>Security Audit Portfolio</span>
                    </div>

                    <h1 className="hero-title">
                        <span className="text-gradient">OWASP Top 10</span>
                        <br />
                        Security Vulnerabilities
                    </h1>

                    <p className="hero-description">
                        Comprehensive security audit portfolio demonstrating {totalTests} exploit tests
                        across all 10 OWASP categories. Each vulnerability includes vulnerable code,
                        secure implementation, and working exploit demonstrations.
                    </p>

                    <div className="hero-actions">
                        <button className="btn btn-primary" onClick={onExplore}>
                            <span>🔍</span>
                            Explore Vulnerabilities
                        </button>
                        <button className="btn btn-secondary" onClick={onAnalyze}>
                            <span>🤖</span>
                            Analyze Your Code
                        </button>
                    </div>

                    <div className="stats-grid" style={{ marginTop: '3rem' }}>
                        <div className="glass-card stat-card">
                            <div className="stat-value">10</div>
                            <div className="stat-label">OWASP Categories</div>
                        </div>
                        <div className="glass-card stat-card">
                            <div className="stat-value">{totalTests}</div>
                            <div className="stat-label">Exploit Tests</div>
                        </div>
                        <div className="glass-card stat-card">
                            <div className="stat-value">100%</div>
                            <div className="stat-label">Tests Passing</div>
                        </div>
                        <div className="glass-card stat-card">
                            <div className="stat-value">45+</div>
                            <div className="stat-label">CVE Templates</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default Hero;
