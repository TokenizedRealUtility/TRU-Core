// Animated terminal background.
#ifndef ANIMATED_BACKGROUND_H
#define ANIMATED_BACKGROUND_H

#include <QWidget>
#include <QPainter>
#include <QTimer>
#include <QRandomGenerator>
#include <vector>
#include <cmath>

class Particle {
public:
    float x, y;
    float vx, vy;
    float size;
    float opacity;
    QColor color;
    
    Particle() {
        reset();
    }
    
    void reset() {
        x = QRandomGenerator::global()->bounded(800);
        y = QRandomGenerator::global()->bounded(600);
        vx = (QRandomGenerator::global()->bounded(100) - 50) / 50.0f;
        vy = (QRandomGenerator::global()->bounded(100) - 50) / 50.0f;
        size = QRandomGenerator::global()->bounded(3) + 1;
        opacity = QRandomGenerator::global()->bounded(100) / 100.0f;
        
        // Cyan to purple gradient
        int r = QRandomGenerator::global()->bounded(100);
        color = QColor(0, 200 + r/2, 255 - r);
    }
    
    void update(int width, int height) {
        x += vx;
        y += vy;
        
        if (x < 0 || x > width) vx = -vx;
        if (y < 0 || y > height) vy = -vy;
    }
};

class AnimatedBackground : public QWidget {
    Q_OBJECT
    
public:
    explicit AnimatedBackground(QWidget *parent = nullptr) : QWidget(parent) {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        
        // Initialize particles
        for (int i = 0; i < 100; ++i) {
            particles.emplace_back();
        }
        
        // Animation timer
        animationTimer = new QTimer(this);
        connect(animationTimer, &QTimer::timeout, this, [this]() {
            updateAnimation();
            update();
        });
        animationTimer->start(30); // 30ms = ~33 FPS
    }
    
protected:
    void paintEvent(QPaintEvent *event) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        
        // Draw connections between nearby particles
        painter.setPen(QPen(QColor(0, 212, 255, 30), 1));
        for (size_t i = 0; i < particles.size(); ++i) {
            for (size_t j = i + 1; j < particles.size(); ++j) {
                float dx = particles[i].x - particles[j].x;
                float dy = particles[i].y - particles[j].y;
                float dist = std::sqrt(dx*dx + dy*dy);
                
                if (dist < 100) {
                    float opacity = (100 - dist) / 100.0f * 30;
                    painter.setPen(QPen(QColor(0, 212, 255, opacity), 1));
                    painter.drawLine(QPointF(particles[i].x, particles[i].y),
                                   QPointF(particles[j].x, particles[j].y));
                }
            }
        }
        
        // Draw particles
        for (const auto& p : particles) {
            painter.setPen(Qt::NoPen);
            QColor c = p.color;
            c.setAlphaF(p.opacity);
            painter.setBrush(c);
            painter.drawEllipse(QPointF(p.x, p.y), p.size, p.size);
        }
        
        // Draw grid overlay
        painter.setPen(QPen(QColor(0, 212, 255, 10), 1));
        for (int x = 0; x < width(); x += 50) {
            painter.drawLine(x, 0, x, height());
        }
        for (int y = 0; y < height(); y += 50) {
            painter.drawLine(0, y, width(), y);
        }
    }
    
private:
    void updateAnimation() {
        for (auto& p : particles) {
            p.update(width(), height());
        }
    }
    
    std::vector<Particle> particles;
    QTimer *animationTimer;
};

// Glowing border effect widget
class GlowBorder : public QWidget {
    Q_OBJECT
    
public:
    explicit GlowBorder(QWidget *parent = nullptr) : QWidget(parent), glowIntensity(0), increasing(true) {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        setAttribute(Qt::WA_TranslucentBackground);
        
        glowTimer = new QTimer(this);
        connect(glowTimer, &QTimer::timeout, this, [this]() {
            if (increasing) {
                glowIntensity += 2;
                if (glowIntensity >= 100) increasing = false;
            } else {
                glowIntensity -= 2;
                if (glowIntensity <= 0) increasing = true;
            }
            update();
        });
        glowTimer->start(20);
    }
    
protected:
    void paintEvent(QPaintEvent *event) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        
        // Draw glowing border
        int alpha = 100 + glowIntensity;
        int spread = 10 + glowIntensity / 10;
        
        for (int i = spread; i > 0; i--) {
            int a = alpha * (spread - i) / spread;
            painter.setPen(QPen(QColor(0, 212, 255, a), i));
            painter.drawRect(rect().adjusted(i/2, i/2, -i/2, -i/2));
        }
    }
    
private:
    QTimer *glowTimer;
    int glowIntensity;
    bool increasing;
};

#endif // ANIMATED_BACKGROUND_H