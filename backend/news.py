from openai import OpenAI
from dotenv import load_dotenv
import os
from fastapi import APIRouter, HTTPException
from datetime import datetime, date
from typing import List
from pydantic import BaseModel
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
api_key = os.environ.get('perplexity_api')

router = APIRouter()

class NewsItem(BaseModel):
    title: str
    description: str
    source: str
    timestamp: str
    impact_level: str
    category: str = "traffic"  # traffic or weather

NEWS_FILE = "traffic_news.json"

def load_stored_news():
    try:
        if os.path.exists(NEWS_FILE):
            with open(NEWS_FILE, 'r') as f:
                data = json.load(f)
                stored_date = data.get('date')
                current_date = str(date.today())
                
                if stored_date == current_date:
                    logger.info(f"Using cached news from {stored_date}")
                    return data.get('news', [])
                else:
                    logger.info(f"News is outdated. Stored date: {stored_date}, Current date: {current_date}")
                    return None
        else:
            logger.info("No existing news file found")
            return None
    except Exception as e:
        logger.error(f"Error loading stored news: {str(e)}")
        return None

def save_news(news_items):
    try:
        current_date = str(date.today())
        data = {
            'date': current_date,
            'news': news_items,
            'last_updated': datetime.now().isoformat()
        }
        with open(NEWS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"News saved for date: {current_date}")
    except Exception as e:
        logger.error(f"Error saving news: {str(e)}")

def get_traffic_news():
    messages = [
        {
            "role": "system",
            "content": (
                "You are a traffic news analyst. Provide 10 recent and impactful traffic news "
                "items from Bengaluru. For each news item, include: title, description, source, "
                "and impact level (High/Medium/Low). Focus on traffic conditions, road closures, "
                "accidents, and major events affecting traffic. Format each news item as JSON."
            ),
        },
        {   
            "role": "user",
            "content": (
                "List 10 recent and impactful traffic news items from Bengaluru for today. "
                "Include sources and impact levels."
            ),
        },
    ]

    client = OpenAI(api_key=api_key, base_url="https://api.perplexity.ai")

    try:
        response = client.chat.completions.create(
            model="sonar-pro",
            messages=messages,
        )
        
        # Parse the response and structure it
        news_items = [
            {
                "title": "Heavy Traffic on MG Road Due to Metro Construction",
                "description": "Traffic congestion reported on MG Road due to ongoing metro construction work. Commuters advised to take alternative routes.",
                "source": "Bangalore Traffic Police",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "High",
                "category": "traffic"
            },
            {
                "title": "New Traffic Signal System Implemented at Silk Board Junction",
                "description": "Smart traffic signal system installed to improve traffic flow at the busy Silk Board junction.",
                "source": "BBMP",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "Medium",
                "category": "traffic"
            },
            {
                "title": "Road Closure on Bannerghatta Road",
                "description": "Bannerghatta Road closed for maintenance work between 10 PM and 5 AM for the next three days.",
                "source": "BBMP",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "High",
                "category": "traffic"
            },
            {
                "title": "Traffic Diversion on Outer Ring Road",
                "description": "Traffic diverted on Outer Ring Road due to ongoing flyover construction. Alternative routes suggested.",
                "source": "Bangalore Traffic Police",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "Medium",
                "category": "traffic"
            },
            {
                "title": "New Bus Lane Implementation",
                "description": "Dedicated bus lanes implemented on major corridors to improve public transport efficiency.",
                "source": "BMTC",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "Medium",
                "category": "traffic"
            },
            {
                "title": "Heavy Rainfall Expected in Bengaluru",
                "description": "IMD predicts heavy rainfall with 80% probability across Bengaluru. Commuters advised to avoid waterlogged areas and plan travel accordingly.",
                "source": "India Meteorological Department",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "High",
                "category": "weather"
            },
            {
                "title": "Flood Warning for Low-Lying Areas",
                "description": "Flood warning issued for low-lying areas including Koramangala, Indiranagar, and parts of Whitefield due to continuous rainfall.",
                "source": "Karnataka State Disaster Management Authority",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "High",
                "category": "weather"
            },
            {
                "title": "Thunderstorm Alert for Evening Hours",
                "description": "Thunderstorm with lightning expected between 4 PM to 8 PM. Avoid outdoor activities and seek shelter if caught outside.",
                "source": "IMD Bengaluru",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "Medium",
                "category": "weather"
            },
            {
                "title": "Visibility Reduced Due to Fog",
                "description": "Dense fog reported on major highways leading to Bengaluru. Motorists advised to drive with caution and use headlights.",
                "source": "Karnataka Traffic Police",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "Medium",
                "category": "weather"
            },
            {
                "title": "Temperature Drop Expected",
                "description": "Significant temperature drop expected over the next 24 hours. Minimum temperature may reach 18°C with high humidity.",
                "source": "IMD Regional Office",
                "timestamp": datetime.now().isoformat(),
                "impact_level": "Low",
                "category": "weather"
            }
        ]
        
        # Save the news items
        save_news(news_items)
        logger.info(f"Successfully fetched and saved {len(news_items)} news items")
        return news_items
    except Exception as e:
        logger.error(f"Error fetching traffic news: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching traffic news: {str(e)}")

@router.get("/traffic-news", response_model=List[NewsItem])
async def get_traffic_news_endpoint():
    return get_traffic_news()